// we can have multiple categories
trait Category {
    fn parse_sexpr(Sexpr) -> Box<Blob>;
}
trait CategoryNodeInner : Any {
}
struct CategoryNode {
    size: u64,
    inner: Box<CategoryNodeInner>,
}
struct CategoryData {
    cat: Category,
    BTreeMap<VMA, CategoryNode>
}
struct RangeDB {
    category_data: HashMap<String, CategoryData>,
}
