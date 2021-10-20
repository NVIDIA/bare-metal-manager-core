//! Generate human readable digests for UUIDs
//!
//! Based on https://github.com/zacharyvoase/humanhash
//! Should be compatible

extern crate uuid;
use uuid::Uuid;

/// Class for custom humanhashers
pub struct HumanHasher {
    words: Wordlist,
}

/// List of 256 strings usable for human readable hash digests
pub type Wordlist = &'static [&'static str; 256];

/// Instance of human hasher with default wordlist
const DEFAULT_HUMANIZER: HumanHasher = HumanHasher { words: DEFAULT_WORDLIST };

/// Default Wordlist, chosen to match the original Python Human Hash
pub const DEFAULT_WORDLIST: Wordlist = &[
    "ack", "alabama", "alanine", "alaska", "alpha", "angel", "apart", "april",
    "arizona", "arkansas", "artist", "asparagus", "aspen", "august", "autumn",
    "avocado", "bacon", "bakerloo", "batman", "beer", "berlin", "beryllium",
    "black", "blossom", "blue", "bluebird", "bravo", "bulldog", "burger",
    "butter", "california", "carbon", "cardinal", "carolina", "carpet", "cat",
    "ceiling", "charlie", "chicken", "coffee", "cola", "cold", "colorado",
    "comet", "connecticut", "crazy", "cup", "dakota", "december", "delaware",
    "delta", "diet", "don", "double", "early", "earth", "east", "echo",
    "edward", "eight", "eighteen", "eleven", "emma", "enemy", "equal",
    "failed", "fanta", "fifteen", "fillet", "finch", "fish", "five", "fix",
    "floor", "florida", "football", "four", "fourteen", "foxtrot", "freddie",
    "friend", "fruit", "gee", "georgia", "glucose", "golf", "green", "grey",
    "hamper", "happy", "harry", "hawaii", "helium", "high", "hot", "hotel",
    "hydrogen", "idaho", "illinois", "india", "indigo", "ink", "iowa",
    "island", "item", "jersey", "jig", "johnny", "juliet", "july", "jupiter",
    "kansas", "kentucky", "kilo", "king", "kitten", "lactose", "lake", "lamp",
    "lemon", "leopard", "lima", "lion", "lithium", "london", "louisiana",
    "low", "magazine", "magnesium", "maine", "mango", "march", "mars",
    "maryland", "massachusetts", "may", "mexico", "michigan", "mike",
    "minnesota", "mirror", "mississippi", "missouri", "mobile", "mockingbird",
    "monkey", "montana", "moon", "mountain", "muppet", "music", "nebraska",
    "neptune", "network", "nevada", "nine", "nineteen", "nitrogen", "north",
    "november", "nuts", "october", "ohio", "oklahoma", "one", "orange",
    "oranges", "oregon", "oscar", "oven", "oxygen", "papa", "paris", "pasta",
    "pennsylvania", "pip", "pizza", "pluto", "potato", "princess", "purple",
    "quebec", "queen", "quiet", "red", "river", "robert", "robin", "romeo",
    "rugby", "sad", "salami", "saturn", "september", "seven", "seventeen",
    "shade", "sierra", "single", "sink", "six", "sixteen", "skylark", "snake",
    "social", "sodium", "solar", "south", "spaghetti", "speaker", "spring",
    "stairway", "steak", "stream", "summer", "sweet", "table", "tango", "ten",
    "tennessee", "tennis", "texas", "thirteen", "three", "timing", "triple",
    "twelve", "twenty", "two", "uncle", "undress", "uniform", "uranus", "utah",
    "vegan", "venus", "vermont", "victor", "video", "violet", "virginia",
    "washington", "west", "whiskey", "white", "william", "winner", "winter",
    "wisconsin", "wolfram", "wyoming", "xray", "yankee", "yellow", "zebra",
    "zulu" ];

/// Human Hasher
impl HumanHasher {
    /// Create a new hasher with a custom wordlist
    pub fn new(words: Wordlist) -> HumanHasher {
        HumanHasher { words: words }
    }

    /// Create a human readable digest for a UUID. Makes the collision space worse,
    /// reducing it to 1:(2^(8*`words_out`)-1).
    pub fn humanize(&self, uuid: &Uuid, words_out: usize) -> String {
        compress(uuid.as_bytes(), words_out)
            .iter()
            .map(|&x| self.words[x as usize].to_string())
            .collect::<Vec<String>>()
            .join("-")
    }
}

/// Break a slice of u8s into (at least) `target` `u8`s.
///
/// WARNING: If the slice is not evenly divisible, there will be one extra u8
/// from the remainder. output `u8`s are created by XORing the input bytes.
fn compress(bytes: &[u8], target: usize) -> Vec<u8> {
    let seg_size = bytes.len() / target;
    bytes.chunks(seg_size)
        .map(|c| c.iter().fold(0u8, |acc, &x| acc ^ x))
        .collect::<Vec<u8>>()
}

/// Create a human readable digest for a UUID. Makes the collision space worse,
/// reducing it to 1:(2^(8*`words_out`)-1).
pub fn humanize(uuid: &Uuid, words_out: usize) -> String {
    DEFAULT_HUMANIZER.humanize(uuid, words_out)
}

#[cfg(test)]
mod tests {
    use super::uuid::Uuid;
    use super::DEFAULT_WORDLIST;
    use super::{humanize, HumanHasher};

    const TEST_UUID: &'static str = "bc0f47f93dd046578d7eee645999b95e";

    #[test]
    fn it_works() {
        let tuid = Uuid::parse_str(TEST_UUID).unwrap();

        assert_eq!(humanize(&tuid, 4), "august-yankee-lima-coffee");

        assert_eq!("pip", humanize(&tuid, 1));
        assert_eq!("washington-hot", humanize(&tuid, 2));
        assert_eq!("august-yankee-lima-coffee", humanize(&tuid, 4));
        assert_eq!("princess-sad-victor-bakerloo-whiskey-mike-saturn-uniform",
                   humanize(&tuid, 8));

    }

    #[test]
    fn class_works() {
        let tuid = Uuid::parse_str(TEST_UUID).unwrap();

        let hzr = HumanHasher::new(&DEFAULT_WORDLIST);

        assert_eq!(humanize(&tuid, 4), hzr.humanize(&tuid, 4));
    }
}
