#![allow(non_snake_case)]
use clap::{ ArgAction, Arg, Command };
use std::collections::HashMap;
use ldap3::result::Result;
use ldap3::{Scope, LdapResult, LdapConn, LdapConnSettings, ResultEntry, SearchEntry};

 
// https://datatracker.ietf.org/doc/html/rfc4511#page-49
// https://docs.rs/ldap3/latest/ldap3/index.html
// https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53
// https://docs.rs/clap/latest/clap/


#[derive(Debug)]
struct CertTemplate {
    dn: String,
    msPKI_Certificate_Policy: Vec<String>,
}

fn buildCertTemplate(distinguished_name: String, Issuance_Policy_OID: Vec<String>) -> CertTemplate {
   CertTemplate {
       dn: distinguished_name,
       msPKI_Certificate_Policy: Issuance_Policy_OID,
   } 
}

#[derive(Clone, Debug)]
struct IssuanceTemplate {
    dn: String,
    msPKI_Cert_Template_OID: Vec<String>,
    msDS_OIDToGroupLink: Option<Vec<String>>,
}

fn buildIssuancePolicy(distinguished_name: String, Cert_Template_OID: Vec<String>, groupLink: Option<Vec<String>>) -> IssuanceTemplate {
    IssuanceTemplate {
        dn: distinguished_name,
        msPKI_Cert_Template_OID: Cert_Template_OID,
        msDS_OIDToGroupLink: groupLink,
    }
}

fn format_result(result: ResultEntry) -> (String, HashMap<String, Vec<String>>) {
    let stack_result = SearchEntry::construct(result);
    return (stack_result.dn.to_string(), stack_result.attrs)
}

fn main() -> Result<()> {
    let cli_args = Command::new("args")
        .arg(Arg::new("ipv4")
             .short('i')
             .long("ip")
             .action(ArgAction::Set)
             .value_name("IPv4")
             .help("IPv4 Address of DC. If -k or --kerberos is used then the FQDN of the server is required.")
             .required(true))
        .arg(Arg::new("username")
             .short('u')
             .long("username")
             .action(ArgAction::Set)
             .value_name("DN")
             .help("Disinguished Name of Domain user to authenticate with.")
             .required(false))
        .arg(Arg::new("password")
             .short('p')
             .long("password")
             .action(ArgAction::Set)
             .help("User password.")
             .required(false))
        .arg(Arg::new("TLS")
             .short('Z')
             .long("req-tls")
             .action(ArgAction::SetTrue)
             .help("Encrypt connection.")
             .required(false))
        .arg(Arg::new("Kerberos")
             .short('k')
             .long("kerberos")
             .action(ArgAction::SetTrue)
             .help("Use kerberos to authenticate. \"username\" and \"password\" arguments are not required here.")
             .required(false))
        .arg(Arg::new("Domain")
             .short('d')
             .long("domain")
             .action(ArgAction::Set)
             .help("Base Domain name. i.e. \"DC=domain,DC=local\".")
             .required(true))
        .get_matches();

    let ip_addr: &str = &cli_args.get_one::<String>("ipv4").unwrap().as_str();
    let mut ldap_server: String = String::from("ldap://");
    ldap_server.push_str(ip_addr);
    let domain_base: &str = &cli_args.get_one::<String>("Domain").unwrap().as_str();
    let mut TemplateContainer: String = String::from("CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,");
    TemplateContainer.push_str(domain_base);
    let mut OIDContainer: String = String::from("CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,");
    OIDContainer.push_str(domain_base);
    let mut Templates_with_IssuancePolicies: Vec<CertTemplate> = Vec::new();
    let mut Issuance_Policies: Vec<IssuanceTemplate> = Vec::new();
    let settings: LdapConnSettings;
    let mut ldap: LdapConn;
    let authenticate: Result<LdapResult>;

    // Decide on StartTLS.
    let tls_true = &cli_args.get_one::<bool>("TLS").unwrap();
    match tls_true {
        true => {
            settings = LdapConnSettings::new().set_no_tls_verify(true).set_starttls(true);
            ldap = LdapConn::with_settings(settings, ldap_server.as_str())?;
        },
        false => { ldap = LdapConn::new(ldap_server.as_str())?; }
    }

    // Kerberos.
    let kerb_true = &cli_args.get_one::<bool>("Kerberos").unwrap();
    match kerb_true {
        true => { authenticate = ldap.sasl_gssapi_bind(ip_addr); },
        false => { 
            let domain_user: &str = &cli_args.get_one::<String>("username").unwrap().as_str();
            let password: &str = &cli_args.get_one::<String>("password").unwrap().as_str();
            authenticate = ldap.simple_bind(domain_user, password); 
        }
    }

    // Ensure successful bind. Code 49 usually means bad credentials.
    match authenticate {
        Ok(res) if res.rc == 0 => println!("[+] Got a successful bind. LDAP Result Code: {}", res.rc),
        _ => panic!("[-] Bind unsuccessful. Most likely bad credentials; Verify LDAP Result Code: {}", authenticate.unwrap().rc),
    };

    // Search Template Container first in order to retrieve all templates.
    let (results, _search_result) = ldap.search(
        &TemplateContainer,
        Scope::Subtree,
        "(msPKI-Certificate-Policy=*)",
        vec!["*"]
        )?.success()?;

    // Go through the templates and organize them into another struct that contains the DN and
    // msPKI-Certificate-Policy. Also makes sure value is not null.
    for result in results {
        let (template_dn, template_properties) = format_result(result);

        for (property, value) in template_properties.into_iter() {
            if property == "msPKI-Certificate-Policy" && !value[0].is_empty() {
                Templates_with_IssuancePolicies.push(buildCertTemplate(template_dn.clone(), value.to_vec()));
            } else {
                continue
            }
        }
    }

    // Search for Issuance Policies.
    let (results, _search_result) = ldap.search(
        &OIDContainer,
        Scope::Subtree,
        "(&(msPKI-Cert-Template-OID=*)(msDS-OIDToGroupLink=*))",
        vec!["*"]
        )?.success()?;

    // Get Issuance Policy property "msDS-Cert-Template-OID" OID value. 
    // Make sure value is not null.
    // Get Issuance Policy property "msDS-OIDToGroupLink" Value.
    // Make sure value is not null.
    for result in results {
        let (template_dn, template_properties) = format_result(result);
        
        // Find msPKI-Cert-Template-OID. 
        for (property, value) in template_properties.clone().into_iter() {
            if "msPKI-Cert-Template-OID".to_string() == property && !value[0].is_empty() {
                Issuance_Policies.push(buildIssuancePolicy(template_dn.clone(), value.to_vec(), None));
            }
        }

        // Iterate again to avoid integer overflow if the previous loop did not meet conditional.
        // If you know a better way to do it, go nuts.
        // Find msDS-OIDToGroupLink and add it to the last IssuanceTemplate.
        for (property, value) in template_properties.into_iter() {
            if "msDS-OIDToGroupLink".to_string() == property && !value[0].is_empty() { 
                let index = Issuance_Policies.len()-1;
                Issuance_Policies[index].msDS_OIDToGroupLink = Some(value.to_vec());
            }
        }
    }

    // Compare Cert Policy OID to Cert Template OID
    for template in Templates_with_IssuancePolicies {
        for templateOid in template.msPKI_Certificate_Policy.into_iter() {
            // For the template, I only want policies that are associated with it
            let matched_oid: Vec<IssuanceTemplate> = Issuance_Policies.clone()
                .into_iter()
                .filter(|x| x.msPKI_Cert_Template_OID.iter().next().unwrap() == &templateOid)
                .collect();

            if matched_oid.is_empty() { continue; }

            // If policy contains group link(s), collect it.
            let linkedGroups: Vec<IssuanceTemplate> = matched_oid
                .into_iter()
                .filter(|x| x.msDS_OIDToGroupLink != None)
                .collect();
            
            println!("[+] Looking for group links in template \"{}\"", template.dn.split(",").collect::<Vec<&str>>()[0]);

            if linkedGroups.is_empty() { continue; }

            let group = linkedGroups[0].msDS_OIDToGroupLink.clone().unwrap();
            if !group.is_empty() {
                let issuancePolicyDN = &linkedGroups[0].dn;
                println!("[*] Linked to group(s) \"{:#?}\" via \"{}\"", group, issuancePolicyDN);
            }
        }
        println!("\n[~]\n");
    }
    Ok(ldap.unbind()?)
}
