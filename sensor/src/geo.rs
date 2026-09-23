use maxminddb::{geoip2, Mmap, Reader};
use std::net::IpAddr;
use std::path::Path;

#[derive(Default, Clone, Debug)]
pub struct Location {
    pub country: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

pub struct Geo {
    reader: Option<Reader<Mmap>>,
}

impl Geo {
    pub fn open(path: Option<&Path>) -> Self {
        // SAFETY: never modify the database file in place; replace it (install/mv) and restart.
        let reader = path.and_then(|p| match unsafe { Reader::open_mmap(p) } {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("geo: could not open {}: {e}; continuing without locations", p.display());
                None
            }
        });
        Geo { reader }
    }

    pub fn lookup(&self, ip: IpAddr) -> Location {
        let Some(reader) = &self.reader else {
            return Location::default();
        };
        let city = match reader.lookup(ip).and_then(|r| r.decode::<geoip2::City>()) {
            Ok(Some(c)) => c,
            _ => return Location::default(),
        };
        Location {
            country: city.country.iso_code.map(str::to_owned),
            city: city.city.names.english.map(str::to_owned),
            lat: city.location.latitude,
            lon: city.location.longitude,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs a real database: HIVE_TEST_GEOIP_DB=/path/to/city.mmdb cargo test -- --ignored
    #[test]
    #[ignore]
    fn reads_a_city_database() {
        let path = std::env::var("HIVE_TEST_GEOIP_DB").expect("set HIVE_TEST_GEOIP_DB");
        let geo = Geo::open(Some(Path::new(&path)));
        let loc = geo.lookup("8.8.8.8".parse().unwrap());
        eprintln!("{loc:?}");
        assert_eq!(loc.country.as_deref(), Some("US"));
        assert!(loc.lat.is_some() && loc.lon.is_some());
        assert!(geo.lookup("127.0.0.1".parse().unwrap()).country.is_none());
    }
}
