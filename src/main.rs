use std::{
    io::{self},
    iter::Peekable,
    process::exit,
};

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

impl Token {
    pub fn new(value: String, token_type: TokenType) -> Self {
        return Self {
            value, token_type
        }
    }
}

fn is_valid_next_token(is_start: bool, current_token: &Token, next_token: Option<&Token>) -> bool {
    if is_start {
        match current_token.token_type {
            TokenType::Number => (),
            TokenType::Operator => return false,
            TokenType::Paren => {
                if current_token.value != "(" {
                    return false;
                }
            }
        }
    }

    if let Some(next_t) = next_token {
        // Default checks if next token exists
        match current_token.token_type {
            // A number may be followed by an operator or a closing paren (implicit multiplication is not allowed)
            TokenType::Number => {
                return next_t.token_type == TokenType::Operator
                    || next_t.token_type == TokenType::Paren && next_t.value == ")";
            }
            // An operator may be followed by a number or an opening paren
            TokenType::Operator => {
                return next_t.token_type == TokenType::Number
                    || next_t.token_type == TokenType::Paren && next_t.value == "(";
            }
            // An opening parent may be followed by a number
            TokenType::Paren if current_token.value == "(" => {
                return next_t.token_type == TokenType::Number; // TODO: Allow "-" operator
            }
            // A closing paren may be followed by an operator
            TokenType::Paren => return next_t.token_type == TokenType::Operator,
        }
    } else {
        // At the end of the term we have to do some different checks
        match current_token.token_type {
            TokenType::Number => return true,
            TokenType::Operator => return false,
            TokenType::Paren => return current_token.value == ")",
        }
    }
}

/// This function assumes that the input string contains only values found in allowed_chars!
fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens: Vec<Token> = vec![];

    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '0'..='9' | '.' => {
                let mut token = Token::new(c.to_string(), TokenType::Number);

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
                tokens.push(Token::new(
                    c.to_string(),
                    TokenType::Operator,
                ));
            }
            '(' | ')' => {
                tokens.push(Token::new(
                    c.to_string(),
                    TokenType::Paren,
                ));
            }
            ' ' => continue, // ignore whitespaces
            _ => continue, // ignore all other characters. Should never happen as this function assumes only valid characters are part of the input
        }
    }

    return tokens;
}

#[cfg(test)]
fn do_basic_token_checks_test(input: &str) -> bool {
    let tokens = tokenize(input);
    return do_basic_token_checks(&tokens);
}

/// Does some basic checks on the tokens (count, no 1.2.3, etc.)
fn do_basic_token_checks(tokens: &Vec<Token>) -> bool {
    if tokens.len() == 0 {
        return false;
    }

    if tokens.first() == None || tokens.last() == None {
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
            }
            _ => (),
        }
    }

    return true;
}

#[cfg(test)]
fn verify_parentheses_test(input: &str) -> bool {
    let tokens = tokenize(input);
    return verify_parentheses(&tokens);
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

fn peek_next<'a, T>(iter: &mut Peekable<T>) -> Option<&'a Token>
where
    T: Iterator<Item = &'a Token>,
{
    iter.peek().cloned()
}

#[cfg(test)]
fn verify_grammar_test(input: &str) -> bool {
    let tokens = tokenize(input);
    return verify_grammar(&tokens);
}

/// verifies the grammar of the tokens (is the sequence of tokens valid)
fn verify_grammar(tokens: &Vec<Token>) -> bool {
    let mut is_start = true;
    let mut iter_ref = tokens.iter().peekable();
    while let Some(current_token) = iter_ref.next() {
        let next_token = peek_next(&mut iter_ref);
        if is_valid_next_token(is_start, current_token, next_token) {
            is_start = false;
            continue;
        }

        return false;
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
    let result = do_basic_token_checks(&tokens);
    if result == false {
        return result;
    }

    let result = verify_parentheses(&tokens);
    if result == false {
        return result;
    }

    let result = verify_grammar(&tokens);
    if result == false {
        return result;
    }

    return true;
}

// Handles numbers and parentheses
fn parse_factor<'a, T>(iter_ref: &mut Peekable<T>) -> f64
where
    T: Iterator<Item = &'a Token>,
{
    let token = peek_next(iter_ref);
    if token.is_none() {
        eprintln!("parse_factor: Token is None!");
        exit(1);
    }

    let token = token.unwrap();
    if token.token_type == TokenType::Number {
        iter_ref.next();
        return token.value.parse::<f64>().unwrap_or(0.0);
    } else if token.token_type == TokenType::Paren && token.value == "(" {
        iter_ref.next();
        let value = parse_expression(iter_ref);
        let next_token = iter_ref.peek();
        if next_token.is_none() {
            eprintln!("parse_factor: Next token is none!");
            exit(1);
        }
        let next_token = next_token.unwrap();
        if next_token.value != ")" {
            eprintln!(
                "parse_factor: Expected closing paren but got {}",
                next_token.value
            );
            exit(1);
        }
        iter_ref.next();
        return value;
    } else {
        eprintln!("Unexpected token in factor: {}", token.value);
        exit(1);
    }
}

// handles * and /
fn parse_term<'a, T>(iter_ref: &mut Peekable<T>) -> f64
where
    T: Iterator<Item = &'a Token>,
{
    let mut value = parse_factor(iter_ref);
    while let Some(next_token) = peek_next(iter_ref)
        && (next_token.value == "*" || next_token.value == "/")
    {
        iter_ref.next();
        let right = parse_factor(iter_ref);
        if next_token.value == "*" {
            value *= right;
        } else {
            value /= right;
        }
    }
    return value;
}

// handles + and -
fn parse_expression<'a, T>(iter_ref: &mut Peekable<T>) -> f64
where
    T: Iterator<Item = &'a Token>,
{
    let mut value = parse_term(iter_ref);
    while let Some(next_token) = peek_next(iter_ref)
        && (next_token.value == "+" || next_token.value == "-")
    {
        iter_ref.next();
        let right = parse_term(iter_ref);
        if next_token.value == "+" {
            value += right;
        } else {
            value -= right;
        }
    }

    return value;
}

fn solve(input: &str) -> f64 {
    let tokens = tokenize(input);
    let mut iter_ref = tokens.iter().peekable();
    let result = parse_expression(&mut iter_ref);
    return result;
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
    if !is_valid {
        println!("Invalid input.");
        return Ok(());
    }

    let result = solve(&input);
    println!("Result: {result}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_solve() {
        let input = "1 + 2";
        let actual = solve(input);
        let expected = 3.0;
        assert_eq!(actual, expected);

        let input = "2 * 2";
        let actual = solve(input);
        let expected = 4.0;
        assert_eq!(actual, expected);

        let input = "2 * 2 - 1";
        let actual = solve(input);
        let expected = 3.0;
        assert_eq!(actual, expected);

        let input = "2 * (2 - 1)";
        let actual = solve(input);
        let expected = 2.0;
        assert_eq!(actual, expected);

        let input = "5 / 2.5";
        let actual = solve(input);
        let expected = 2.0;
        assert_eq!(actual, expected);

        let input = "(4 * (3 - 1)) / 2";
        let actual = solve(input);
        let expected = 4.0;
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_is_valid_next_token_operator() {
        let is_start = true;
        let current_token =  Token::new("+".to_string(), TokenType::Operator);
        let next_token: Option<&Token> = None;
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("+".to_string(), TokenType::Operator);
        let next_token =  Some(&Token::new("5".to_string(), TokenType::Number));
        let expected = true;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("+".to_string(), TokenType::Operator);
        let next_token =  Some(&Token::new("(".to_string(), TokenType::Paren));
        let expected = true;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("+".to_string(), TokenType::Operator);
        let next_token =  Some(&Token::new(")".to_string(), TokenType::Paren));
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("+".to_string(), TokenType::Operator);
        let next_token: Option<&Token> = None;
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("+".to_string(), TokenType::Operator);
        let next_token: Option<&Token> = None;
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_is_valid_next_token_number() {
        let is_start = true;
        let current_token =  Token::new("1".to_string(), TokenType::Number);
        let next_token: Option<&Token> = Some(&Token::new("5".to_string(), TokenType::Number));
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("1".to_string(), TokenType::Number);
        let next_token: Option<&Token> = Some(&Token::new("5".to_string(), TokenType::Number));
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("1".to_string(), TokenType::Number);
        let next_token: Option<&Token> = Some(&Token::new("+".to_string(), TokenType::Operator));
        let expected = true;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("1".to_string(), TokenType::Number);
        let next_token: Option<&Token> = Some(&Token::new("(".to_string(), TokenType::Paren));
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("1".to_string(), TokenType::Number);
        let next_token: Option<&Token> = Some(&Token::new(")".to_string(), TokenType::Paren));
        let expected = true;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("1".to_string(), TokenType::Number);
        let next_token: Option<&Token> = None;
        let expected = true;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_is_valid_next_token_paren() {
        let is_start = true;
        let current_token =  Token::new("(".to_string(), TokenType::Paren);
        let next_token: Option<&Token> = Some(&Token::new(")".to_string(), TokenType::Paren));
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = true;
        let current_token =  Token::new("(".to_string(), TokenType::Paren);
        let next_token: Option<&Token> = Some(&Token::new("5".to_string(), TokenType::Number));
        let expected = true;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = true;
        let current_token =  Token::new("(".to_string(), TokenType::Paren);
        let next_token: Option<&Token> = Some(&Token::new("+".to_string(), TokenType::Operator)); // TODO: Allow operator
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = true;
        let current_token =  Token::new(")".to_string(), TokenType::Paren);
        let next_token: Option<&Token> = Some(&Token::new(")".to_string(), TokenType::Paren));
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("(".to_string(), TokenType::Paren);
        let next_token: Option<&Token> = Some(&Token::new("5".to_string(), TokenType::Number));
        let expected = true;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("(".to_string(), TokenType::Paren);
        let next_token: Option<&Token> = Some(&Token::new("+".to_string(), TokenType::Operator));
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new(")".to_string(), TokenType::Paren);
        let next_token: Option<&Token> = Some(&Token::new("+".to_string(), TokenType::Operator));
        let expected = true;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new(")".to_string(), TokenType::Paren);
        let next_token: Option<&Token> = Some(&Token::new("5".to_string(), TokenType::Number));
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new(")".to_string(), TokenType::Paren);
        let next_token: Option<&Token> = None;
        let expected = true;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);

        let is_start = false;
        let current_token =  Token::new("(".to_string(), TokenType::Paren);
        let next_token: Option<&Token> = None;
        let expected = false;
        let actual = is_valid_next_token(is_start, &current_token, next_token);
        assert_eq!(actual, expected);
    }

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
        let input = "";
        let res = do_basic_token_checks_test(&input);
        assert_eq!(res, false);

        let input = "1 + 2.5 - (2) / 3 * 5";
        let res = do_basic_token_checks_test(&input);
        assert_eq!(res, true);

        let input = ".5";
        let res = do_basic_token_checks_test(&input);
        assert_eq!(res, false);

        let input = "5.";
        let res = do_basic_token_checks_test(&input);
        assert_eq!(res, false);

        let input = ".";
        let res = do_basic_token_checks_test(&input);
        assert_eq!(res, false);

        let input = "1.2.5";
        let res = do_basic_token_checks_test(&input);
        assert_eq!(res, false);
    }

    #[test]
    fn test_verify_parentheses() {
        let input = "()";
        let res = verify_parentheses_test(&input);
        assert_eq!(res, true);

        let input = ")(";
        let res = verify_parentheses_test(&input);
        assert_eq!(res, false);

        let input = "(()";
        let res = verify_parentheses_test(&input);
        assert_eq!(res, false);
    }

    #[test]
    fn test_verify_grammar() {
        let input = "1 + 1 - (4 - 5)";
        let res = verify_grammar_test(&input);
        assert_eq!(res, true);

        let input = "1 * 1";
        let res = verify_grammar_test(&input);
        assert_eq!(res, true);

        let input = "1 * -";
        let res = verify_grammar_test(&input);
        assert_eq!(res, false);

        let input = "1 * 1 (";
        let res = verify_grammar_test(&input);
        assert_eq!(res, false);

        let input = "12 34";
        let res = verify_grammar_test(&input);
        assert_eq!(res, false);

        let input = "+ 34 -";
        let res = verify_grammar_test(&input);
        assert_eq!(res, false);

        let input = "(34 - 2)";
        let res = verify_grammar_test(&input);
        assert_eq!(res, true);

        let input = "()";
        let res = verify_grammar_test(&input);
        assert_eq!(res, false);

        let input = "+-";
        let res = verify_grammar_test(&input);
        assert_eq!(res, false);
    }
}
