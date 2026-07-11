use super::QueryPage;

#[test]
fn test_query_page_exposes_entries_and_next_cursor() {
    let page = QueryPage::new([1, 2, 3], Some(3));

    assert_eq!(page.entries(), &[1, 2, 3]);
    assert_eq!(page.next_cursor(), Some(&3));
}
