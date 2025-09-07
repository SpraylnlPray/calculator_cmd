use std::{io, ops::Index, process::exit};

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

fn validate_tokens(tokens: Vec<Token>) -> bool {
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

fn is_valid_input(input: &str, allowed_chars: &Vec<char>) -> bool {
    if input.len() == 0 {
        return false;
    }

    if input.chars().any(|c: char| !allowed_chars.contains(&c)) {
        return false;
    }

    let tokens = tokenize(input);
    let result = validate_tokens(tokens);

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
        // res.get(index)
        // assert_eq!(Some(&40), v.get(1));
    }

    #[test]
    fn test_validate_tokens() {
        let input = vec![];
        let res = validate_tokens(input);
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
        let res = validate_tokens(input);
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
        let res = validate_tokens(input);
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
        let res = validate_tokens(input);
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
        let res = validate_tokens(input);
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
        let res = validate_tokens(input);
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
        let res = validate_tokens(input);
        assert_eq!(res, false);

        let input = vec![
            Token {
                token_type: TokenType::Number,
                value: ".5".to_string(),
            },
        ];
        let res = validate_tokens(input);
        assert_eq!(res, false);

        let input = vec![
            Token {
                token_type: TokenType::Number,
                value: "5.".to_string(),
            },
        ];
        let res = validate_tokens(input);
        assert_eq!(res, false);

        let input = vec![
            Token {
                token_type: TokenType::Number,
                value: ".".to_string(),
            },
        ];
        let res = validate_tokens(input);
        assert_eq!(res, false);

        let input = vec![
            Token {
                token_type: TokenType::Number,
                value: "1.2.5".to_string(),
            },
        ];
        let res = validate_tokens(input);
        assert_eq!(res, false);
    }
}
