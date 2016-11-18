extern crate regex;
use regex::Regex;
use std::fs;
use std::fs::File;
use std::collections::{BTreeSet, BTreeMap};
use std::io::Read;
use std::ffi::OsStr;
use std::io::Write;
extern crate toml;

static FEATURES: &'static [&'static str] = &[
    "use_llvm",
];

#[macro_use] extern crate lazy_static;
macro_rules! re { ($a:expr) => { {
    lazy_static! {
        static ref RE: Regex = Regex::new($a).unwrap();
    };
    &*RE
} } }

fn main() {
    let mut base_toml_str = String::new();
    File::open("build/gen-cargo-toml/base.toml").unwrap().read_to_string(&mut base_toml_str).unwrap();
    let base_toml = toml::Value::Table(toml::Parser::new(&base_toml_str).parse().unwrap());

    let mut my_crates = BTreeMap::new();
    for subdir in fs::read_dir("src/").unwrap() {
        let subdir = subdir.unwrap();
        if subdir.path().is_dir() {
            let name = subdir.file_name().into_string().unwrap();
            let crate_name = name.replace("-", "_");
            my_crates.insert(crate_name, name);
        }
    }
    for (crate_name, ref subdir) in &my_crates {
        let without_hyphens = re!("^.*-").replace_all(subdir, "");
        let main_file = format!("{}.rs", without_hyphens);
        let mut dep_crates = BTreeSet::new();
        let mut build_dep_crates = BTreeSet::new();
        let mut is_bin = false;
        let mut have_build_rs = false;
        for file in fs::read_dir(format!("src/{}", subdir)).unwrap() {
            let file = file.unwrap().path();
            if file.extension() != Some(OsStr::new("rs")) { continue; }
            let is_build_rs = file.file_name().unwrap() == "build.rs";
            if is_build_rs { have_build_rs = true; }
            let mut data = String::new();
            File::open(file).unwrap().read_to_string(&mut data).unwrap();
            if !is_build_rs && re!(r"(?:^|\n|] )fn main\(\)").find(&data).is_some() {
                is_bin = true;
            }
            for decl in re!("(?:^|\n|] )extern crate ([^;]*);").captures_iter(&data) {
                for part in re!(r"\s*,\s*").split(decl.at(1).unwrap()) {
                    let dep_crate = re!(" as .*").replace_all(part, "");
                    (if is_build_rs { &mut build_dep_crates }
                               else { &mut dep_crates }).insert(dep_crate);
                }
            }
        }

        let mut package = toml::Table::new();
        package.insert("name".to_owned(), toml::Value::String(crate_name.to_owned()));
        package.insert("version".to_owned(), toml::Value::String(format!("0.0.0")));
        if have_build_rs {
            package.insert("build".to_owned(), toml::Value::String(format!("build.rs")));
        }
        let mut lib = toml::Table::new();
        lib.insert("path".to_owned(), toml::Value::String(main_file));
        let mut features = toml::Table::new();
        for &feat in FEATURES {
            features.insert(feat.to_owned(), toml::Value::Array(Vec::new()));
        }
        let mut dependencies = toml::Table::new();
        let mut build_dependencies = toml::Table::new();

        for (x_dep_crates, x_dependencies) in vec![
            (&dep_crates, &mut dependencies),
            (&build_dep_crates, &mut build_dependencies),
        ] {
            for orig_dep_crate in x_dep_crates {
                let mut dep_crate = orig_dep_crate.to_owned();
                let gate_feature =
                    if dep_crate.contains("llvm") { Some("use_llvm") }
                    else { None };

                let key = format!("dependencies.{}", dep_crate);
                let mut dep = if let Some(dep_subdir) = my_crates.get(&dep_crate) {
                    let mut dep = toml::Table::new();
                    dep.insert("path".to_owned(), toml::Value::String(format!("../{}", dep_subdir)));
                    dep.insert("version".to_owned(), toml::Value::String(format!("=0.0.0")));
                    for &feat in FEATURES {
                        if let toml::Value::Array(ref mut ary) = *features.get_mut(feat).unwrap() {
                            ary.push(toml::Value::String(format!("{}/{}", dep_crate, feat)));
                        } else { panic!() }
                    }
                    dep
                } else if dep_crate == "alloc_system" {
                    continue
                } else {
                    let mut tab =
                        base_toml.lookup(&key).expect(&format!("missing {} from {}", key, subdir))
                        .as_table().unwrap().to_owned();
                    if let Some(real_name) = tab.remove("name") {
                        dep_crate = real_name.as_str().unwrap().to_owned();
                    }
                    tab
                };
                if let Some(feat) = gate_feature {
                    dep.insert("optional".to_owned(), toml::Value::Boolean(true));
                    if let toml::Value::Array(ref mut ary) = *features.get_mut(feat).unwrap() {
                        ary.push(toml::Value::String(dep_crate.to_owned()));
                    } else { panic!() }
                }
                x_dependencies.insert(dep_crate.to_owned(), toml::Value::Table(dep));
            }
        }
        let mut cargo_toml = toml::Table::new();
        cargo_toml.insert("dependencies".to_owned(), toml::Value::Table(dependencies));
        cargo_toml.insert("build-dependencies".to_owned(), toml::Value::Table(build_dependencies));
        cargo_toml.insert("features".to_owned(), toml::Value::Table(features));
        cargo_toml.insert("package".to_owned(), toml::Value::Table(package));
        if is_bin {
            lib.insert("name".to_owned(), toml::Value::String(without_hyphens));
            cargo_toml.insert("bin".to_owned(), toml::Value::Array(vec![
                toml::Value::Table(lib)
            ]));
        } else {
            cargo_toml.insert("lib".to_owned(), toml::Value::Table(lib));
        }
        let outpath = format!("src/{}/Cargo.toml", subdir);
        let outdata = format!("# Autogenerated by gen-cargo-toml (but checked in)\n{}",
                              toml::Value::Table(cargo_toml));
        if let Ok(mut fp) = File::open(&outpath) {
            let mut existing = String::new();
            fp.read_to_string(&mut existing).unwrap();
            if existing == outdata { continue; }
        }
        write!(File::create(outpath).unwrap(), "{}", outdata).unwrap();
    }


}

