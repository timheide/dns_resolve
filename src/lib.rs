use std::str::FromStr;

use domain::base::{Dname, Question, Rtype};
use domain::base::iana::Class;
use domain::base::name::UncertainDname;
use domain::base::net::Ipv4Addr;
use domain::rdata::rfc1035::A;
use domain_resolv::StubResolver;

/// decode the raw dns result
pub async fn decode_dns(name: &Dname<Vec<u8>>, resolver: &StubResolver) -> Result<Vec<Ipv4Addr>, String> {
    let mut result: Vec<Ipv4Addr> = Vec::new();
    let question = Question::new(name.clone(), Rtype::A, Class::In);
    let query = resolver.query(question).await.unwrap();
    for record in query.answer().unwrap().limit_to::<A>() {
        match record {
            Ok(x) => {
                result.push(x.clone().into_data().addr());
            }
            Err(_) => {}
        }
    }
    Ok(result)
}

///resolve a dns
#[tokio::main]
pub async fn resolve_dns(name: String) -> Result<Vec<Ipv4Addr>, String> {
    let resolver = StubResolver::new();
    if let Ok(name) = UncertainDname::from_str(&name) {
        match name {
            UncertainDname::Absolute(ref name) => {
                decode_dns(name, &resolver).await
            }
            UncertainDname::Relative(ref name) => {
                let test = name.clone().into_absolute().unwrap();
                decode_dns(&test, &resolver).await
            }
        }
    } else {
        Err(format!("Not a domain name: {}", name))
    }
}