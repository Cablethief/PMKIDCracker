use base64;
use clap::{App, Arg};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha1::Sha1;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

// extern crate crypto;

fn main() {
    let matches = App::new("PMKID Cracker")
        .version("1.0")
        .author("Michael Kruger <@_Cablethief>")
        .about("Cracks PMKID using CPU")
        .arg(
            Arg::with_name("wordlist")
                .short("w")
                .long("wordlist")
                .help("Sets the wordlist to use")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("pmkid")
                .short("p")
                .long("pmkid")
                .help("Sets the pmkid to crack")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .get_matches();

    let wordlist = matches.value_of("wordlist").unwrap();

    let parse_pmkid: Vec<&str> = matches
        .value_of("pmkid")
        .unwrap()
        .split(|c| c == '*')
        .collect();

    // Check for PMKID formatting
    let pmkid = check_pmkid_formatting(parse_pmkid);

    println!(
        "PMKID: {}\nAP MAC: {}\nSTA MAC: {}\nSSID: {}",
        pmkid[0], pmkid[1], pmkid[2], pmkid[3]
    );

    // File hosts must exist in current path before this produces output
    if let Ok(lines) = read_lines(wordlist) {
        // Consumes the iterator, returns an (Optional) String
        for line in lines {
            if let Ok(pass_attempt) = line {
                println!("{}", pass_attempt);
                println!(
                    "{}",
                    pbkdf2_wifi(&pass_attempt, pmkid[3])
                        .unwrap()
                        .split(|c| c == '$')
                        .collect::<Vec<&str>>()[5]
                );
            }
        }
    } else {
        println!("Could not open wordlist!")
    }
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

// Help user if they messed up there PMKID
fn check_pmkid_formatting(pmkid: Vec<&str>) -> Vec<&str> {
    assert_eq!(pmkid.len(), 4, "PMKID Does not match Hashcat Format!");
    assert_eq!(
        pmkid[0].len(),
        32,
        "PMKID: \"{}\", does not match the correct length 32!",
        pmkid[0]
    );
    assert_eq!(
        pmkid[1].len(),
        12,
        "AP MAC: \"{}\", does not match the correct length 12!",
        pmkid[1]
    );
    assert_eq!(
        pmkid[2].len(),
        12,
        "STA MAC: \"{}\", does not match the correct length 12!",
        pmkid[2]
    );
    return pmkid;
}

pub fn pbkdf2_wifi(psk: &str, ssid: &str) -> io::Result<String> {
    // let mut rng = OsRng::new()?;

    // // 128-bit salt
    // let mut salt = [0u8; 16];
    // rng.try_fill_bytes(&mut salt)?;

    // 256-bit derived key
    let mut dk = [0u8; 32];

    pbkdf2::<Hmac<Sha1>>(psk.as_bytes(), &ssid.as_bytes(), 4069 as usize, &mut dk);

    let mut result = &base64::encode(&dk);
    // let mut tmp = [0u8; 4];
    // BigEndian::write_u32(&mut tmp, c);
    // result.push_str(&base64::encode(&tmp));
    // result.push('$');
    // result.push_str(&base64::encode(&salt));
    // result.push('$');
    result.push_str(&base64::encode(&dk));
    // result.push('$');

    Ok(result)
}
