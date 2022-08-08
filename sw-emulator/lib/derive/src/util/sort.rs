/*++

Licensed under the Apache-2.0 license.

File Name:

    sort.rs

Abstract:

    General-purpose functions for sorting.

--*/
pub fn sorted_by_key<K: Ord, T>(
    iter: impl Iterator<Item = T>,
    f: impl FnMut(&T) -> K,
) -> impl DoubleEndedIterator<Item = T> {
    let mut result = Vec::from_iter(iter);
    result.sort_by_key(f);
    result.into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sorted_by_key() {
        assert_eq!(
            vec![5, 3, 1, 0],
            Vec::from_iter(sorted_by_key(vec![5i32, 1, 3, 0].into_iter(), |v| -v))
        );
        assert_eq!(
            vec![0, 1, 3, 5],
            Vec::from_iter(sorted_by_key(vec![5i32, 1, 3, 0].into_iter(), |v| -v).rev())
        );
    }
}
