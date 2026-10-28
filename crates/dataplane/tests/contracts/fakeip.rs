use nm_tunnel_dataplane::{
    dns,
    fakeip::{self, HEADER, Identities},
};
use std::io;

#[test]
fn durable_callback_precedes_publication_and_failed_append_poisons_the_epoch() -> io::Result<()> {
    let mut journal = HEADER.to_vec();
    let mut identities = Identities::restore(&journal)?;
    let first = identities.lookup("First.Example.", |record| {
        journal.extend_from_slice(record);
        Ok(())
    })?;
    let before = journal.clone();
    assert_eq!(
        identities.lookup("first.example", |_| panic!(
            "existing identity must not append"
        ))?,
        first
    );
    assert_eq!(identities.reverse(first)?, "first.example");
    assert!(
        identities
            .lookup("unpublished.example", |_| Err(io::Error::other(
                "Synthetic write failure."
            )))
            .is_err()
    );
    assert!(identities.reverse(first).is_err());
    assert!(
        identities
            .lookup("first.example", |_| panic!(
                "poisoned identity must not append"
            ))
            .is_err()
    );
    assert_eq!(journal, before);
    let mut restored = Identities::restore(&journal)?;
    assert_eq!(restored.reverse(first)?, "first.example");
    let second = restored.lookup("second.example", |record| {
        journal.extend_from_slice(record);
        Ok(())
    })?;
    assert_ne!(first, second);
    Ok(())
}

#[test]
fn malformed_restore_and_ipv6_questions_do_not_allocate_or_reset() -> io::Result<()> {
    for suffix in [
        b"\"first.example\"".as_slice(),
        b"\"first.example\"\n\"first.example\"\n",
        b"\"First.Example\"\n",
    ] {
        let mut bytes = HEADER.to_vec();
        bytes.extend_from_slice(suffix);
        let before = bytes.clone();
        assert!(Identities::restore(&bytes).is_err());
        assert_eq!(bytes, before);
    }
    let (_, bytes) = dns::query("first.example")?;
    let mut query = dns::parse_query(&bytes)?;
    query.queries[0].set_query_type(hickory_proto::rr::RecordType::AAAA);
    let response = fakeip::answer(&query.to_vec().map_err(io::Error::other)?, |_| {
        panic!("AAAA must not allocate")
    })?;
    dns::validate_response(&query, &response)?;
    assert!(
        hickory_proto::op::Message::from_vec(&response)
            .map_err(io::Error::other)?
            .answers
            .is_empty()
    );
    Ok(())
}
