/*++

Licensed under the Apache-2.0 license.

File Name:

    token_iter.rs

Abstract:

    General-purpose functions for manipulating token iterators.

--*/
use std::{collections::HashMap, fmt::Display};

use proc_macro2::{Delimiter, Group, Ident, Literal, Spacing, TokenStream, TokenTree};

pub struct Attribute {
    #[allow(dead_code)]
    pub name: Ident,
    pub args: HashMap<String, TokenTree>,
}

pub struct FieldWithAttributes {
    pub attr_name: String,
    pub field_name: Option<Ident>,
    pub field_type: TokenStream,
    pub attributes: Vec<Attribute>,
}

pub struct DisplayToken<'a>(pub &'a Option<TokenTree>);
impl<'a> Display for DisplayToken<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(TokenTree::Ident(i)) => write!(f, "identifier {}", i),
            Some(TokenTree::Literal(l)) => write!(f, "literal {}", l),
            Some(TokenTree::Punct(p)) => write!(f, "punctuation '{}'", p),
            Some(TokenTree::Group(g)) => write!(f, "group {}", g),
            None => write!(f, "<none>"),
        }
    }
}

#[allow(dead_code)]
pub fn expect_ident_of(iter: &mut impl Iterator<Item = TokenTree>, expected_name: &str) {
    let token = iter.next();
    if let Some(TokenTree::Ident(ref ident)) = token {
        if ident == expected_name {
            return;
        }
    }
    panic!(
        "Expected identifier {}, found {}",
        expected_name,
        DisplayToken(&token)
    )
}

pub fn expect_ident(iter: &mut impl Iterator<Item = TokenTree>) -> Ident {
    let token = iter.next();
    if let Some(TokenTree::Ident(ref ident)) = token {
        return ident.clone();
    }
    panic!("Expected identifier, found {}", DisplayToken(&token))
}

#[allow(dead_code)]
pub fn expect_literal(iter: &mut impl Iterator<Item = TokenTree>) -> Literal {
    let token = iter.next();
    if let Some(TokenTree::Literal(literal)) = token {
        return literal;
    }
    panic!("Expected literal, found {}", DisplayToken(&token))
}

pub fn expect_literal_or_ident(iter: &mut impl Iterator<Item = TokenTree>) -> TokenTree {
    let token = iter.next();
    match token {
        Some(TokenTree::Literal(literal)) => TokenTree::Literal(literal),
        Some(TokenTree::Ident(ident)) => TokenTree::Ident(ident),
        _ => panic!(
            "Expected literal or identifier, found {}",
            DisplayToken(&token)
        ),
    }
}

pub fn expect_punct_of(iter: &mut impl Iterator<Item = TokenTree>, expected: char) {
    let token = iter.next();
    if let Some(TokenTree::Punct(ref punct)) = token {
        if punct.as_char() == expected {
            return;
        }
    }
    panic!(
        "Expected punctuation '{}', found {}",
        expected,
        DisplayToken(&token)
    )
}

pub fn expect_group(iter: &mut impl Iterator<Item = TokenTree>, delimiter: Delimiter) -> Group {
    let token = iter.next();
    if let Some(TokenTree::Group(ref group)) = token {
        if group.delimiter() == delimiter {
            return group.clone();
        }
    }
    panic!(
        "Expected group with delimiter '{:?}', found {}",
        delimiter,
        DisplayToken(&token)
    )
}

pub fn skip_to_struct_with_attributes(iter: &mut impl Iterator<Item = TokenTree>) -> Vec<Group> {
    let mut prev_token_was_hash = false;
    let mut attributes = Vec::new();
    loop {
        match iter.next() {
            Some(TokenTree::Ident(ident)) => {
                if ident == "struct" {
                    return attributes;
                }
            }
            Some(TokenTree::Punct(punct)) if punct.as_char() == '#' => {
                prev_token_was_hash = true;
                continue;
            }
            Some(TokenTree::Group(group))
                if group.delimiter() == Delimiter::Bracket && prev_token_was_hash =>
            {
                attributes.push(group);
            }
            None => panic!("Unexpected end of tokens while searching for struct"),
            _ => {}
        };
        prev_token_was_hash = false;
    }
}

pub fn collect_while(
    iter: &mut impl Iterator<Item = TokenTree>,
    mut pred: impl FnMut(&TokenTree) -> bool,
) -> TokenStream {
    let mut result = TokenStream::new();
    loop {
        match iter.next() {
            Some(t) => {
                if pred(&t) {
                    result.extend(Some(t));
                } else {
                    return result;
                }
            }
            None => return result,
        }
    }
}

pub fn skip_to_group(iter: &mut impl Iterator<Item = TokenTree>, delimiter: Delimiter) -> Group {
    loop {
        match iter.next() {
            Some(TokenTree::Group(group)) => {
                if group.delimiter() == delimiter {
                    return group;
                }
            }
            None => panic!("Unexpected end of tokens while searching for group"),
            _ => {}
        };
    }
}

pub fn skip_to_attribute_or_ident(iter: &mut impl Iterator<Item = TokenTree>) -> Option<TokenTree> {
    loop {
        match iter.next() {
            Some(TokenTree::Punct(punct)) => {
                if punct.as_char() == '#' && punct.spacing() == Spacing::Alone {
                    if let Some(TokenTree::Group(group)) = iter.next() {
                        if group.delimiter() == Delimiter::Bracket {
                            return Some(TokenTree::Group(group));
                        }
                    }
                }
            }
            Some(TokenTree::Ident(ident)) => {
                if ident == "pub" {
                    continue;
                }
                return Some(TokenTree::Ident(ident));
            }
            None => return None,
            _ => {}
        };
    }
}

pub fn skip_to_field_with_attributes(
    iter: &mut impl Iterator<Item = TokenTree>,
    attribute_name_pred: impl Fn(&str) -> bool,
    no_field_required_pred: impl Fn(&Attribute) -> bool,
) -> Option<FieldWithAttributes> {
    let mut attr_name = String::new();
    let mut attributes = Vec::new();
    loop {
        match skip_to_attribute_or_ident(iter) {
            Some(TokenTree::Group(group)) => {
                let mut iter = group.stream().into_iter();
                let attribute_ident = expect_ident(&mut iter);
                attr_name = attribute_ident.to_string();
                if !attribute_name_pred(&attr_name) {
                    continue;
                }
                let params = expect_group(&mut iter, Delimiter::Parenthesis);
                let mut iter = params.stream().into_iter();
                let mut args = HashMap::new();
                loop {
                    let key = expect_ident(&mut iter);
                    expect_punct_of(&mut iter, '=');
                    let value = expect_literal_or_ident(&mut iter);
                    args.insert(key.to_string(), value);
                    let token = iter.next();
                    match token {
                        Some(TokenTree::Punct(ref punct)) => {
                            if punct.as_char() == ',' {
                                continue;
                            }
                        }
                        None => break,
                        _ => {}
                    }
                    panic!("Unexpected token {:?}", token)
                }
                let attribute = Attribute {
                    name: attribute_ident,
                    args,
                };
                attributes.push(attribute);
                if no_field_required_pred(attributes.last().unwrap()) {
                    return Some(FieldWithAttributes {
                        attr_name,
                        field_name: None,
                        field_type: TokenStream::new(),
                        attributes,
                    });
                }
            }
            Some(TokenTree::Ident(ident)) => {
                expect_punct_of(iter, ':');
                let mut depth = 0;
                let field_type = collect_while(iter, |t| match t {
                    TokenTree::Punct(p) if p.as_char() == '<' => {
                        depth += 1;
                        true
                    }
                    TokenTree::Punct(p) if p.as_char() == '>' => {
                        depth -= 1;
                        true
                    }
                    TokenTree::Punct(p) => depth != 0 || p.as_char() != ',',
                    _ => true,
                });

                return Some(FieldWithAttributes {
                    attr_name,
                    field_name: Some(ident),
                    field_type,
                    attributes,
                });
            }
            None => return None,
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use proc_macro2::TokenStream;

    use super::*;

    fn tokens(s: &str) -> impl Iterator<Item = TokenTree> {
        TokenStream::from_str(s).unwrap().into_iter()
    }

    #[test]
    fn test_expect_ident_of() {
        expect_ident_of(&mut tokens("foo"), "foo");
        expect_ident_of(&mut tokens("baz"), "baz");
    }
    #[test]
    #[should_panic(expected = "Expected identifier foo, found identifier bar")]
    fn test_expect_ident_of_panic1() {
        expect_ident_of(&mut tokens("bar"), "foo");
    }
    #[test]
    #[should_panic(expected = "Expected identifier foo, found <none>")]
    fn test_expect_ident_of_panic2() {
        expect_ident_of(&mut tokens(""), "foo");
    }
    #[test]
    #[should_panic(expected = "Expected identifier foo, found literal 35")]
    fn test_expect_ident_of_panic3() {
        expect_ident_of(&mut tokens("35"), "foo");
    }

    #[test]
    fn test_expect_ident() {
        assert_eq!("foo", expect_ident(&mut tokens("foo")).to_string());
    }
    #[test]
    #[should_panic(expected = "Expected identifier, found literal 35")]
    fn test_expect_ident_panic1() {
        expect_ident(&mut tokens("35"));
    }

    #[test]
    fn test_expect_literal() {
        assert_eq!("42", expect_literal(&mut tokens("42")).to_string());
        assert_eq!("'h'", expect_literal(&mut tokens("'h'")).to_string());
    }
    #[test]
    #[should_panic(expected = "Expected literal, found identifier foo")]
    fn test_expect_literal_panic1() {
        expect_literal(&mut tokens("foo"));
    }

    #[test]
    fn test_expect_punct_of() {
        expect_punct_of(&mut tokens(","), ',');
        expect_punct_of(&mut tokens("."), '.');
    }
    #[test]
    #[should_panic(expected = "Expected punctuation '.', found punctuation ','")]
    fn test_expect_punct_of_panic1() {
        expect_punct_of(&mut tokens(","), '.');
    }

    #[test]
    fn test_expect_group() {
        expect_group(&mut tokens("[35, 42]"), Delimiter::Bracket);
        expect_group(&mut tokens("(35, 42)"), Delimiter::Parenthesis);
        expect_group(&mut tokens("{}"), Delimiter::Brace);
    }
    #[test]
    #[should_panic(expected = "Expected group with delimiter 'Bracket', found group (35 , 42)")]
    fn test_expect_group_panic1() {
        expect_group(&mut tokens("(35, 42)"), Delimiter::Bracket);
    }
    #[test]
    #[should_panic(expected = "Expected group with delimiter 'Bracket', found literal 35")]
    fn test_expect_group_panic2() {
        expect_group(&mut tokens("35"), Delimiter::Bracket);
    }

    #[test]
    fn test_skip_to_struct() {
        let iter = &mut tokens("struct { foo: u32 }");
        let attrs = skip_to_struct_with_attributes(iter);
        assert!(attrs.is_empty());
        assert_eq!("{ foo : u32 }", iter.next().unwrap().to_string());

        let iter = &mut tokens("pub struct { foo: u32 }");
        let attrs = skip_to_struct_with_attributes(iter);
        assert!(attrs.is_empty());
        assert_eq!("{ foo : u32 }", iter.next().unwrap().to_string());

        let iter = &mut tokens("pub(crate) struct { foo: u32 }");
        let attrs = skip_to_struct_with_attributes(iter);
        assert!(attrs.is_empty());
        assert_eq!("{ foo : u32 }", iter.next().unwrap().to_string());

        let iter = &mut tokens("#[foobar] pub(crate) struct { foo: u32 }");
        let attrs = skip_to_struct_with_attributes(iter);
        assert_eq!(attrs.len(), 1);
        assert_eq!("[foobar]", attrs[0].to_string());
        assert_eq!("{ foo : u32 }", iter.next().unwrap().to_string());

        let iter = &mut tokens("#[foo(fn = blah)] #[bar] struct { foo: u32 }");
        let attrs = skip_to_struct_with_attributes(iter);
        assert_eq!(attrs.len(), 2);
        assert_eq!("[foo (fn = blah)]", attrs[0].to_string());
        assert_eq!("[bar]", attrs[1].to_string());
        assert_eq!("{ foo : u32 }", iter.next().unwrap().to_string());
    }

    #[test]
    fn test_skip_to_group() {
        assert_eq!(
            "(35 , 42)",
            skip_to_group(&mut tokens("(35, 42)"), Delimiter::Parenthesis).to_string()
        );
        assert_eq!(
            "(35 , 42)",
            skip_to_group(
                &mut tokens("foo bar baz 0xff #(35, 42)"),
                Delimiter::Parenthesis
            )
            .to_string()
        );
        assert_eq!(
            "(35 , 42)",
            skip_to_group(&mut tokens("Hi [foo, 32] (35, 42)"), Delimiter::Parenthesis).to_string()
        );
        assert_eq!(
            "[foo , 32]",
            skip_to_group(&mut tokens("Hi [foo, 32] (35, 42)"), Delimiter::Bracket).to_string()
        );
    }
    #[test]
    #[should_panic(expected = "Unexpected end of tokens")]
    fn test_skip_to_group_panic1() {
        skip_to_group(&mut tokens("Hi [foo, 32] (35, 42)"), Delimiter::Brace);
    }

    #[test]
    fn test_skip_to_attribute_or_ident() {
        assert_eq!(
            "[something (foo = 5)]",
            skip_to_attribute_or_ident(&mut tokens(": , #[something(foo = 5)]"))
                .unwrap()
                .to_string()
        );
        assert_eq!(
            "foo",
            skip_to_attribute_or_ident(&mut tokens(": , foo"))
                .unwrap()
                .to_string()
        );
        assert_eq!(
            "foo",
            skip_to_attribute_or_ident(&mut tokens(": , pub foo"))
                .unwrap()
                .to_string()
        );
        assert!(skip_to_attribute_or_ident(&mut tokens(": , ")).is_none());
    }

    #[test]
    fn test_skip_to_field_with_attributes() {
        let result = skip_to_field_with_attributes(
            &mut tokens(
                "#[attr1(a = 35)] #[attr2(b = 42)] #[attr1(a = 65, baz=\"hi\")] pub foo: Foo,",
            ),
            |name| name == "attr1",
            |_| false,
        )
        .unwrap();
        assert_eq!("foo", result.field_name.unwrap().to_string());
        assert_eq!("attr1", result.attributes[0].name.to_string());
        assert_eq!(
            "35",
            result.attributes[0].args.get("a").unwrap().to_string()
        );
        assert_eq!("attr1", result.attributes[1].name.to_string());
        assert_eq!(
            "65",
            result.attributes[1].args.get("a").unwrap().to_string()
        );
        assert_eq!(
            "\"hi\"",
            result.attributes[1].args.get("baz").unwrap().to_string()
        );
    }
}
