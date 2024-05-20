use chrono::{DateTime, Local, NaiveDateTime, Utc};
use regex::Regex;
use std::{
    collections::HashMap,
    fmt::Display,
    fs, io,
    net::{AddrParseError, Ipv4Addr},
    path::Path,
    str::FromStr,
};

// TODO: failover support
// TODO: ipv6 support

#[derive(Debug)]
pub enum BindingState {
    Active,
    Free,
    Abandoned,
}

impl Display for BindingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            BindingState::Active => "active",
            BindingState::Free => "free",
            BindingState::Abandoned => "abandoned",
        };
        write!(f, "{s}")
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Invalid binding state: {0}")]
pub struct BindingStateParseError(String);

impl FromStr for BindingState {
    type Err = BindingStateParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "free" => Ok(Self::Free),
            "active" => Ok(Self::Active),
            "abandoned" => Ok(Self::Abandoned),
            other => Err(BindingStateParseError(other.to_owned())),
        }
    }
}

#[derive(Debug)]
pub enum HWType {
    Ethernet,
}

#[derive(Debug)]
pub struct Hardware {
    pub hwtype: HWType,
    pub addr: String,
}

#[derive(thiserror::Error, Debug)]
pub enum HardwareParseError {
    #[error("Invalid hardware: {0}")]
    Invalid(String),
}

impl FromStr for Hardware {
    type Err = HardwareParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let words = s.split(' ').collect::<Vec<&str>>();
        if words.len() < 2 {
            return Err(Self::Err::Invalid(s.to_owned()));
        }
        let (hw_type_s, hw_addr_s) = (words[0], words[1]);

        let hw_type = match hw_type_s {
            "ethernet" => HWType::Ethernet,
            _ => return Err(Self::Err::Invalid(s.to_owned())),
        };

        Ok(Self {
            hwtype: hw_type,
            addr: hw_addr_s.to_owned(),
        })
    }
}

#[derive(Debug)]
pub struct Var {
    pub key: String,
    pub val: String,
}

#[derive(Debug)]
pub struct Lease {
    pub ip_addr: Ipv4Addr,
    pub starts: DateTime<Utc>,
    pub ends: DateTime<Utc>,
    pub cltt: DateTime<Utc>,
    pub tstp: Option<DateTime<Utc>>,

    pub binding_state: BindingState,
    pub next_binding_state: Option<BindingState>,
    pub rewind_binding_state: Option<BindingState>,

    pub hardware: Hardware,
    pub uid: Option<String>,
    pub hostname: Option<String>,

    pub variables: Vec<Var>,
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Invalid Lease format:\n{0}")]
    Format(String),

    #[error("Error parsing IP address:\n{source}")]
    IpAddr {
        #[from]
        source: AddrParseError,
    },

    #[error("Invalid time: {0}")]
    Time(String),

    #[error("Field missing: {0:?}")]
    Missing(Field),

    #[error("Invalid binding state:\n{source}")]
    BindingState {
        #[from]
        source: BindingStateParseError,
    },

    #[error("Invalid hardware:\n{source}")]
    Hardware {
        #[from]
        source: HardwareParseError,
    },

    #[error("Emtpy lease")]
    Empty,

    #[error("Fields leftover after parsing: {0:?}")]
    UnhandledFields(Vec<String>),
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub enum Field {
    Starts,
    Ends,
    Cltt,
    Tstp,

    BindingState,
    NextBindingState,
    RewindBindingState,

    Hardware,
    Uid,
    Hostname,
    Variable,
}

#[derive(Debug)]
pub struct Parser {
    regex_map: HashMap<Field, Regex>,
}

/// Helper struct with methods to identify and parse lease block fields.
/// Stores the compiled regexs to avoid multiple compilation.
/// To use it, one must seed it with field lines to parse using input().
/// Then you can get parsed fields out of it with caps() with which you can
/// build a Lease object.
impl Parser {
    pub fn new() -> Self {
        Self {
            regex_map: Self::regex_map(),
        }
    }

    fn get_lease_block_delim_regex() -> (Regex, Regex) {
        let ip4_addr_p = r"(?:[0-9]{1,3}.){3}[0-9]{1,3}";
        let start_p = &format!("lease ({}) {}", ip4_addr_p, r"\{");
        let end_p = r"}";

        let start_r =
            Regex::new(start_p).expect("This is based on static strings");
        let end_r = Regex::new(end_p).expect("This is based on static strings");

        (start_r, end_r)
    }

    fn caps(
        &self,
        field_lines: &mut Vec<String>,
        field: Field,
    ) -> Result<Vec<String>, ParseError> {
        let regex = self.regex_map.get(&field).unwrap();

        // Find the first line that matches regex for given field and remove it
        let matching_line = {
            let mut matching_line: Option<String> = None;
            for i in 0..field_lines.len() {
                if regex.is_match(&field_lines[i]) {
                    matching_line = Some(field_lines.remove(i));
                    break;
                }
            }
            matching_line
        };

        let line = matching_line.ok_or(ParseError::Missing(field))?;
        let caps = regex
            .captures(&line)
            .expect("The regex is static")
            .iter()
            .flatten()
            .map(|m| m.as_str().to_owned())
            .collect();

        Ok(caps)
    }

    fn regex_map() -> HashMap<Field, Regex> {
        let mut regexes = HashMap::new();

        let date_r = r"[0-9]{4}/[0-9]{2}/[0-9]{2}";
        let time_r = r"[0-9]{2}:[0-9]{2}:[0-9]{2}";
        let timestamp_r = &format!("[0-9] ({date_r} {time_r})");

        regexes.insert(
            Field::Starts,
            Regex::new(&format!(r"^starts {timestamp_r};")).unwrap(),
        );
        regexes.insert(
            Field::Ends,
            Regex::new(&format!(r"^ends {timestamp_r};")).unwrap(),
        );
        regexes.insert(
            Field::Cltt,
            Regex::new(&format!(r"^cltt {timestamp_r};")).unwrap(),
        );
        regexes.insert(
            Field::Tstp,
            Regex::new(&format!(r"^tstp {timestamp_r};")).unwrap(),
        );

        regexes.insert(
            Field::BindingState,
            Regex::new(r"^binding state (\w+);").unwrap(),
        );
        regexes.insert(
            Field::NextBindingState,
            Regex::new(r"^next binding state (\w+);").unwrap(),
        );
        regexes.insert(
            Field::RewindBindingState,
            Regex::new(r"^rewind binding state (\w+);").unwrap(),
        );

        regexes.insert(
            Field::Hardware,
            Regex::new(r"^hardware (\w+ .+);").unwrap(),
        );
        regexes.insert(Field::Uid, Regex::new(r#"uid "(.+)";"#).unwrap());
        regexes.insert(
            Field::Hostname,
            Regex::new(r#"^client-hostname "(.+)";"#).unwrap(),
        );

        regexes.insert(
            Field::Variable,
            Regex::new(r#"^set (.+) = "(.+)";"#).unwrap(),
        );

        regexes
    }
}

fn time_from_str(s: &str) -> Result<DateTime<Utc>, ParseError> {
    let date_fmt = "%Y/%m/%d %H:%M:%S";

    let local_t = NaiveDateTime::parse_from_str(s, date_fmt)
        .map_err(|_| ParseError::Time(s.to_owned()))?
        .and_local_timezone(Local);

    match local_t {
        chrono::LocalResult::Single(t) => Ok(t.with_timezone(&Utc)),
        _ => unreachable!("Right?"),
    }
}

impl Parser {
    /// Just reads the given file and looks for lease blocks by scanning over the lines
    pub fn parse_file(
        &self,
        file: &Path,
    ) -> Result<Vec<Lease>, ListParseError> {
        let contents = fs::read_to_string(file)?;
        let lines: Vec<&str> = contents.lines().collect();
        let mut leases: Vec<Lease> = Vec::new();

        let mut i: usize = 0;
        // j starts at i+1, so i up to len()-2
        while i < lines.len() - 2 {
            // This is the start of a lease block
            if lines[i].starts_with("lease ") {
                // Search for the end of the block
                for j in i + 1..lines.len() {
                    if lines[j] == "}" {
                        let lease_block = &lines[i..=j].join("\n");
                        let lease =
                            self.parse_lease(lease_block).map_err(|e| {
                                ListParseError::from_lease_err(e, i, j)
                            })?;
                        leases.push(lease);
                        i = j; // Continue the outter loop after this block
                        break;
                    }
                }
            }
            i += 1;
        }

        Ok(leases)
    }

    // TODO I dont feel like learning a parser right now, but this should
    // probably be a proper grammar. For now just regexes
    /// Create a Lease struct from a lease block like in dhcpd.leases
    fn parse_lease(&self, s: &str) -> Result<Lease, ParseError> {
        let lines: Vec<&str> = s.lines().collect();

        let (first_line, last_line) = match (lines.first(), lines.last()) {
            (None, None) => return Err(ParseError::Empty),
            (Some(l1), Some(l2)) => (l1, l2),
            _ => unreachable!("Only reason first/last fail is because empty"),
        };

        let (header_r, footer_r) = Parser::get_lease_block_delim_regex();
        if !header_r.is_match(first_line) || !footer_r.is_match(last_line) {
            return Err(ParseError::Format(format!(
                "{first_line}\n...\n{last_line}"
            )));
        }

        let ip_addr = header_r.captures(first_line).expect("Regexs are static")
            [1]
        .parse::<Ipv4Addr>()?;

        // Isolate the lines containing the fields
        let mut field_lines = lines[1..lines.len() - 1]
            .iter()
            .map(|l| l.trim().to_owned())
            .collect::<Vec<String>>();
        if field_lines.is_empty() {
            return Err(ParseError::Empty);
        }

        let starts =
            time_from_str(&self.caps(&mut field_lines, Field::Starts)?[1])?;
        let ends =
            time_from_str(&self.caps(&mut field_lines, Field::Ends)?[1])?;
        let cltt =
            time_from_str(&self.caps(&mut field_lines, Field::Cltt)?[1])?;

        let binding_state = BindingState::from_str(
            &self.caps(&mut field_lines, Field::BindingState)?[1],
        )?;

        let hardware = Hardware::from_str(
            &self.caps(&mut field_lines, Field::Hardware)?[1],
        )?;

        // Optional fields
        let uid = self
            .caps(&mut field_lines, Field::Uid)
            .ok()
            .map(|caps| caps[1].clone());
        let tstp = self
            .caps(&mut field_lines, Field::Tstp)
            .ok()
            .map(|caps| time_from_str(&caps[1]))
            .transpose()?;
        let next_binding_state = self
            .caps(&mut field_lines, Field::NextBindingState)
            .ok()
            .map(|caps| BindingState::from_str(&caps[1]))
            .transpose()?;
        let rewind_binding_state = self
            .caps(&mut field_lines, Field::RewindBindingState)
            .ok()
            .map(|caps| BindingState::from_str(&caps[1]))
            .transpose()?;
        let hostname = self
            .caps(&mut field_lines, Field::Hostname)
            .ok()
            .map(|caps| caps[1].clone());

        let variables = {
            let mut vars = Vec::new();
            // Repeat this because there can be multiple variables
            // Additionally, it is fine to catch this Err() value here
            // since it is also valid for there to be 0 variables
            while let Ok(caps) = self.caps(&mut field_lines, Field::Variable) {
                let var = Var {
                    key: caps[1].clone(),
                    val: caps[2].clone(),
                };
                vars.push(var);
            }
            vars
        };

        if field_lines.is_empty() {
            Ok(Lease {
                ip_addr,
                starts,
                ends,
                cltt,
                tstp,
                binding_state,
                next_binding_state,
                rewind_binding_state,
                hardware,
                uid,
                hostname,
                variables,
            })
        } else {
            Err(ParseError::UnhandledFields(field_lines))
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ListParseError {
    #[error("Could not open file:\n{source}")]
    FileOpen {
        #[from]
        source: io::Error,
    },

    #[error("Error parsing lease on lines {start_l}-{end_l}:\n{source}")]
    ParseLease {
        source: ParseError,
        start_l: usize,
        end_l: usize,
    },
}

impl ListParseError {
    fn from_lease_err(
        source: ParseError,
        start_l: usize,
        end_l: usize,
    ) -> Self {
        ListParseError::ParseLease {
            source,
            start_l,
            end_l,
        }
    }
}

#[test]
fn test_parse_lease() {
    let lease_str = r#"lease 192.168.1.207 {
  starts 6 2024/05/18 14:22:16;
  ends 0 2024/05/19 14:22:16;
  tstp 0 2024/05/19 14:22:16;
  cltt 6 2024/05/18 14:22:16;
  binding state free;
  hardware ethernet 18:6c:3f:1d:f7:47;
  uid "\001\024\108\063\029\247\071";
  set vendor-class-identifier = "MSFT 5.0";
}"#;

    eprintln!("Testing with lease:\n{lease_str}");
    let parser = Parser::new();
    let lease = parser.parse_lease(lease_str);

    eprintln!("{:?}", lease);
    assert!(lease.is_ok());
}

#[test]
fn test_read_lease_file() {
    let lease_file: std::path::PathBuf = "tests/dhcpd.leases".into();
    eprintln!("Testing with lease file: {lease_file:?}");
    let parser = Parser::new();
    let lease_list = parser.parse_file(&lease_file);

    eprintln!("{:?}", lease_list);
    assert!(lease_list.is_ok());
}
