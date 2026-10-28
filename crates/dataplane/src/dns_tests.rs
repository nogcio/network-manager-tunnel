use super::*;
use hickory_proto::{
    op::{MessageType, OpCode},
    rr::{
        Record,
        rdata::{A, CNAME},
    },
};

#[test]
fn direct_dns_authorization_binds_question_and_answer_chain_not_unrelated_a_records()
-> Result<(), Box<dyn std::error::Error>> {
    let name = Name::from_utf8("direct.example.")?;
    let other = Name::from_utf8("unrelated.example.")?;
    let ip: Ipv4Addr = "1.1.1.1".parse()?;
    let mut response = Message::new(42, MessageType::Response, OpCode::Query);
    response.add_query(Query::query(name.clone(), RecordType::A));
    response.add_answer(Record::from_rdata(other.clone(), 60, RData::A(A(ip))));
    let bytes = response.to_vec()?;
    assert!(!direct_dns_answer(42, "direct.example", ip.into(), &bytes)?);
    assert!(!direct_dns_answer(
        42,
        "different.example",
        ip.into(),
        &bytes
    )?);
    assert!(direct_dns_answer(43, "direct.example", ip.into(), &bytes).is_err());
    response.add_answer(Record::from_rdata(name, 60, RData::CNAME(CNAME(other))));
    assert!(direct_dns_answer(
        42,
        "direct.example",
        ip.into(),
        &response.to_vec()?
    )?);
    assert!(!direct_dns_answer(
        42,
        "direct.example",
        Ipv4Addr::new(8, 8, 8, 8).into(),
        &response.to_vec()?
    )?);
    response.answers[0].dns_class = hickory_proto::rr::DNSClass::CH;
    assert!(!direct_dns_answer(
        42,
        "direct.example",
        ip.into(),
        &response.to_vec()?
    )?);
    response.answers[0].dns_class = hickory_proto::rr::DNSClass::IN;
    response.metadata.op_code = OpCode::Update;
    assert!(!direct_dns_answer(
        42,
        "direct.example",
        ip.into(),
        &response.to_vec()?
    )?);
    response.metadata.op_code = OpCode::Query;
    response.metadata.truncation = true;
    assert!(direct_dns_answer(42, "direct.example", ip.into(), &response.to_vec()?).is_err());
    Ok(())
}
