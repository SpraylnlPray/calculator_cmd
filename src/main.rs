use std::{cell::RefCell, io, iter::Peekable, ops::Index, process::exit, rc::Rc};

/// Possible extensions:
/// - allow signs on numbers (e.g. 4 + -5)
/// - add powers?

fn clean_console() {
    #[cfg(target_family = "windows")]
    {
        std::process::Command::new("cmd")
            .args(&["/C", "cls"])
            .status()
            .unwrap_or_else(|status| {
                println!(
                    "An error occurred while clearing the screen: {}, exit.",
                    status.to_string()
                );
                exit(-1);
            });
    }
    #[cfg(target_family = "unix")]
    {
        std::process::Command::new("clear")
            .status()
            .unwrap_or_else(|status| {
                println!(
                    "An error occurred while clearing the screen: {}, exit.",
                    status.to_string()
                );
                exit(-1);
            });
    }
}

pub fn get_input() -> Result<String, std::io::Error> {
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            if let Some('\n') = input.chars().next_back() {
                input.pop();
            }
            if let Some('\r') = input.chars().next_back() {
                input.pop();
            }
            return Ok(input);
        }
        Err(err) => Err(err),
    }
}

#[derive(Debug, PartialEq)]
enum TokenType {
    Number,
    Operator,
    Paren,
}

#[derive(Debug, PartialEq)]
struct Token {
    value: String,
    token_type: TokenType,
}

/// This function assumes that the input string contains only values found in allowed_chars!
fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens: Vec<Token> = vec![];

    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '0'..='9' | '.' => {
                let mut token = Token {
                    token_type: TokenType::Number,
                    value: c.to_string(),
                };

                while let Some(&d) = chars.peek() {
                    match d {
                        '0'..='9' | '.' => {
                            token.value.push(d);
                            chars.next();
                        }
                        _ => break,
                    }
                }

                tokens.push(token);
            }
            '/' | '*' | '+' | '-' => {
                tokens.push(Token {
                    value: c.to_string(),
                    token_type: TokenType::Operator,
                });
            }
            '(' | ')' => {
                tokens.push(Token {
                    value: c.to_string(),
                    token_type: TokenType::Paren,
                });
            }
            ' ' => continue, // ignore whitespaces
            _ => continue, // ignore all other characters. Should never happen as this function assumes only valid characters are part of the input
        }
    }

    return tokens;
}

/// Does some basic checks on the tokens (count, first/last token, no (), no 1.2.3, etc.)
fn do_basic_token_checks(tokens: &Vec<Token>) -> bool {
    if tokens.len() == 0 {
        return false;
    }

    if tokens.first() == None || tokens.last() == None {
        return false;
    }

    // unwrap is safe because we checked if first is None
    if tokens.first().unwrap().token_type != TokenType::Number
        && tokens.first().unwrap().value != "("
    {
        return false;
    }

    // unwrap is safe because we checked if last is None
    if tokens.last().unwrap().token_type != TokenType::Number && tokens.last().unwrap().value != ")"
    {
        return false;
    }

    let mut iter = tokens.iter().peekable();
    while let Some(t) = iter.next() {
        match t.token_type {
            TokenType::Number => {
                if t.value.starts_with('.') || t.value.ends_with('.') {
                    // disallow .5 and 5.
                    return false;
                }
                if t.value.matches('.').count() > 1 {
                    // disallow .
                    return false;
                }

                if let Some(&nt) = iter.peek() {
                    if nt.token_type == TokenType::Number {
                        // disallow 12 34
                        return false;
                    }
                }
            }
            TokenType::Operator => {
                if let Some(&nt) = iter.peek() {
                    if nt.token_type == TokenType::Operator {
                        // disallow e.g. +-
                        return false;
                    }
                }
            }
            TokenType::Paren => {
                if let Some(&nt) = iter.peek() {
                    if nt.token_type == TokenType::Paren && nt.value != t.value {
                        // disallow ()
                        return false;
                    }
                }
            }
        }
    }

    return true;
}

/// verifies parentheses are valid
fn verify_parentheses(tokens: &Vec<Token>) -> bool {
    let mut count = 0;
    for token in tokens {
        if token.token_type != TokenType::Paren {
            continue;
        }

        if token.value == "(" {
            count += 1;
            continue;
        }

        if token.value == ")" {
            if count == 0 {
                return false;
            }

            count -= 1;
        }
    }

    return count == 0;
}

fn parse_expression<'a, T>(iter: &mut Peekable<T>) -> bool
where
    T: Iterator<Item = &'a Token>,
{
    if !parse_term(iter) {
        return false;
    }

    while let Some(t) = peek_next(iter) {
        match t.value.as_str() {
            "+" | "-" => {
                println!("parse_expression: {}", t.value);
                iter.next();

                if !parse_term(iter) {
                    return false;
                }
            }
            _ => println!("parse_expression, found value {}", t.value),
        }
    }

    return true;
}

fn parse_term<'a, T>(iter: &mut Peekable<T>) -> bool
where
    T: Iterator<Item = &'a Token>,
{
    if !parse_factor(iter) {
        return false;
    }

    while let Some(t) = peek_next(iter) {
        match t.value.as_str() {
            "*" | "/" => {
                println!("parse_term: {}", t.value);
                iter.next();

                if !parse_factor(iter) {
                    return false;
                }

                return true;
            }
            _ => {
                println!("parse_term, found value {}", t.value);
                return false;
            }
        }
    }

    return true;
}

fn peek_next<'a, T>(iter: &mut Peekable<T>) -> Option<&'a Token>
where
    T: Iterator<Item = &'a Token>,
{
    iter.peek().cloned()
}

fn parse_factor<'a, T>(iter: &mut Peekable<T>) -> bool
where
    T: Iterator<Item = &'a Token>,
{
    while let Some(t) = peek_next(iter) {
        if t.value == "+" || t.value == "-" {
            iter.next();
            return parse_factor(iter);
        }

        if t.token_type == TokenType::Number {
            iter.next();
            return true;
        }

        if t.value == "(" {
            iter.next();
            if !parse_expression(iter) {
                return false;
            }

            if let Some(t) = peek_next(iter) {
                if t.value != ")" {
                    return false;
                }
                iter.next();
                return true;
            } else {
                return false;
            }
        }
    }
    return false;
}

/// verifies the grammar of the tokens (is the sequence of tokens valid)
fn verify_grammar(tokens: &Vec<Token>) -> bool {
    let mut iter_ref = tokens.iter().peekable();
    let res = parse_expression(&mut iter_ref);

    if res == true && iter_ref.peek().is_none() {
        return true;
    }

    return false;
}

fn is_valid_input(input: &str, allowed_chars: &Vec<char>) -> bool {
    if input.len() == 0 {
        return false;
    }

    if input.chars().any(|c: char| !allowed_chars.contains(&c)) {
        return false;
    }

    let tokens = tokenize(input);
    let result = do_basic_token_checks(&tokens);
    if result == false {
        return result;
    }

    let result = verify_parentheses(&tokens);
    if result == false {
        return result;
    }

    return true;
}

fn main() -> Result<(), std::io::Error> {
    let allowed_chars: Vec<char> = vec![
        '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '(', ')', ' ', '+', '-', '*', '/', '.',
    ];
    clean_console();
    println!("Enter term to calculate:");
    let input = get_input()?;
    println!("Received {input}");
    let is_valid = is_valid_input(&input, &allowed_chars);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_is_valid_calculation() {
        let allowed_chars: Vec<char> = vec![
            '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '(', ')', ' ', '+', '-', '*', '/',
            '.',
        ];

        let input = "";
        let res = is_valid_input(input, &allowed_chars);
        assert_eq!(res, false, "Should be false");

        let input = "1a + 2";
        let res = is_valid_input(input, &allowed_chars);
        assert_eq!(res, false, "Should be false");

        let input = "1 + 2";
        let res = is_valid_input(input, &allowed_chars);
        assert_eq!(res, true, "Should be true");

        let input = "123";
        let res = is_valid_input(input, &allowed_chars);
        assert_eq!(res, true, "Should be true");

        let input = "1 + 2.5 - (4 - 3) * 2 / 3";
        let res = is_valid_input(input, &allowed_chars);
        assert_eq!(res, true, "Should be true");
    }

    #[test]
    fn test_tokenize() {
        let input = "1 + 2.5 - (2) / 3 * 5";
        let expected = vec![
            Token {
                token_type: TokenType::Number,
                value: "1".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "+".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "2.5".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "-".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: "(".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "2".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: ")".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "/".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "3".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "*".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "5".to_string(),
            },
        ];
        let res = tokenize(input);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_do_basic_token_checks() {
        let input = vec![];
        let res = do_basic_token_checks(&input);
        assert_eq!(res, false);

        let input = vec![
            Token {
                token_type: TokenType::Number,
                value: "1".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "+".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "2.5".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "-".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: "(".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "2".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: ")".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "/".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "3".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "*".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "5".to_string(),
            },
        ];
        let res = do_basic_token_checks(&input);
        assert_eq!(res, true);

        let input = vec![
            Token {
                token_type: TokenType::Number,
                value: "12".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "34".to_string(),
            },
        ];
        let res = do_basic_token_checks(&input);
        assert_eq!(res, false);

        let input = vec![
            Token {
                token_type: TokenType::Operator,
                value: "+".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "34".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "-".to_string(),
            },
        ];
        let res = do_basic_token_checks(&input);
        assert_eq!(res, false);

        let input = vec![
            Token {
                token_type: TokenType::Paren,
                value: "(".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "34".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "-".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "2".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: ")".to_string(),
            },
        ];
        let res = do_basic_token_checks(&input);
        assert_eq!(res, true);

        let input = vec![
            Token {
                token_type: TokenType::Paren,
                value: "(".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: ")".to_string(),
            },
        ];
        let res = do_basic_token_checks(&input);
        assert_eq!(res, false);

        let input = vec![
            Token {
                token_type: TokenType::Operator,
                value: "+".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "-".to_string(),
            },
        ];
        let res = do_basic_token_checks(&input);
        assert_eq!(res, false);

        let input = vec![Token {
            token_type: TokenType::Number,
            value: ".5".to_string(),
        }];
        let res = do_basic_token_checks(&input);
        assert_eq!(res, false);

        let input = vec![Token {
            token_type: TokenType::Number,
            value: "5.".to_string(),
        }];
        let res = do_basic_token_checks(&input);
        assert_eq!(res, false);

        let input = vec![Token {
            token_type: TokenType::Number,
            value: ".".to_string(),
        }];
        let res = do_basic_token_checks(&input);
        assert_eq!(res, false);

        let input = vec![Token {
            token_type: TokenType::Number,
            value: "1.2.5".to_string(),
        }];
        let res = do_basic_token_checks(&input);
        assert_eq!(res, false);
    }

    #[test]
    fn test_verify_parentheses() {
        let input = vec![
            Token {
                token_type: TokenType::Paren,
                value: "(".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: ")".to_string(),
            },
        ];
        let res = verify_parentheses(&input);
        assert_eq!(res, true);

        let input = vec![
            Token {
                token_type: TokenType::Paren,
                value: ")".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: "(".to_string(),
            },
        ];
        let res = verify_parentheses(&input);
        assert_eq!(res, false);

        let input = vec![
            Token {
                token_type: TokenType::Paren,
                value: "(".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: "(".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: ")".to_string(),
            },
        ];
        let res = verify_parentheses(&input);
        assert_eq!(res, false);
    }

    #[test]
    fn test_verify_grammar() {
        let input = vec![
            Token {
                token_type: TokenType::Number,
                value: "1".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "+".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "1".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: "-".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: "(".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "4".to_string(),
            },
            Token {
                token_type: TokenType::Operator,
                value: "-".to_string(),
            },
            Token {
                token_type: TokenType::Number,
                value: "5".to_string(),
            },
            Token {
                token_type: TokenType::Paren,
                value: ")".to_string(),
            },
        ];
        let res = verify_grammar(&input);
        assert_eq!(res, true);
    }
}
