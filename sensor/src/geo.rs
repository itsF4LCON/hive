use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;

#[derive(Default, Clone, Debug)]
pub struct Location {
    pub country: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

/// Offline GeoLite2 lookups. Without a database every lookup is empty, which is fine for local testing.
pub struct Geo {
    reader: Option<Reader<Vec<u8>>>,
}

impl Geo {
    pub fn open(path: Option<&Path>) -> Self {
        let reader = path.and_then(|p| match Reader::open_readfile(p) {
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
