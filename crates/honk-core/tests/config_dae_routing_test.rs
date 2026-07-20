// Integration test: load config.dae and verify routing behavior

use honk_config::parser::parse_dae_config;
use honk_core::routing::{ConnectionInfo, Router};

fn make_conn(
    domain: Option<&str>,
    dst_ip: &str,
    dst_port: u16,
    src_ip: &str,
    src_port: u16,
    protocol: &'static str,
) -> ConnectionInfo {
    ConnectionInfo {
        domain: domain.map(|s| s.to_string()),
        dst_ip: dst_ip.parse().unwrap(),
        dst_port,
        src_ip: src_ip.parse().unwrap(),
        src_port,
        protocol,
        process_name: None,
        mac: None,
        dscp: None,
    }
}

#[test]
fn test_routing_with_config_dae() {
    let config_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.dae");
    let config_content = std::fs::read_to_string(config_path).expect("Failed to read config.dae");

    let config = parse_dae_config(&config_content).expect("Failed to parse config.dae");
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound)
        .expect("Failed to build Router");

    println!("Router has {} compiled rules", router.route_count());
    assert!(router.route_count() > 0, "Router should have rules");

    // Test 1: Private IP → direct(must) (geoip:private rule)
    {
        let conn = make_conn(None, "192.168.1.1", 443, "10.10.10.100", 50000, "tcp");
        let result = router.route(&conn);
        println!("✓ Private IP 192.168.1.1:443 → {}", result);
        assert!(
            result.contains("direct"),
            "Private IP should go direct: got {}",
            result
        );
    }

    // Test 2: Public IP port 443 → omg (generic port proxy rule)
    {
        let conn = make_conn(None, "8.8.8.8", 443, "10.10.10.100", 50001, "tcp");
        let result = router.route(&conn);
        println!("✓ Public IP 8.8.8.8:443 → {}", result);
        assert_eq!(result, "omg", "Public IP port 443 should go to omg");
    }

    // Test 3: Public IP port 22 → omg (generic port proxy rule)
    {
        let conn = make_conn(None, "8.8.8.8", 22, "10.10.10.100", 50002, "tcp");
        let result = router.route(&conn);
        println!("✓ Public IP 8.8.8.8:22 → {}", result);
        assert_eq!(result, "omg", "Public IP port 22 should go to omg");
    }

    // Test 4: Port 53 → fallback (direct)
    {
        let conn = make_conn(None, "8.8.8.8", 53, "10.10.10.100", 50003, "udp");
        let result = router.route(&conn);
        println!("✓ Public IP 8.8.8.8:53 → {}", result);
        assert_eq!(result, "direct", "Port 53 should fallback to direct");
    }

    // Test 5: Source IP 10.10.10.8 → omg (generic port proxy rule)
    {
        let conn = make_conn(None, "8.8.8.8", 443, "10.10.10.8", 50004, "tcp");
        let result = router.route(&conn);
        println!("✓ Source 10.10.10.8 → 8.8.8.8:443 → {}", result);
        assert_eq!(result, "omg", "Source IP 10.10.10.8 should go to omg");
    }

    // Test 6: Source IP 10.10.10.4 → omg (generic port proxy rule)
    {
        let conn = make_conn(None, "8.8.8.8", 443, "10.10.10.4", 50005, "tcp");
        let result = router.route(&conn);
        println!("✓ Source 10.10.10.4 → 8.8.8.8:443 → {}", result);
        assert_eq!(result, "omg", "Source IP 10.10.10.4 should go to omg");
    }

    // Test 7: Domain google.com port 443 → hk (geosite: google rule)
    {
        let conn = make_conn(
            Some("www.google.com"),
            "142.250.80.4",
            443,
            "10.10.10.100",
            50006,
            "tcp",
        );
        let result = router.route(&conn);
        println!("✓ google.com:443 → {}", result);
        assert_eq!(result, "hk", "google.com:443 should go to hk");
    }

    // Test 8: Domain suffix jogiyw.sbs → direct (domain rule wins before port rule)
    {
        let conn = make_conn(
            Some("test.jogiyw.sbs"),
            "1.2.3.4",
            443,
            "10.10.10.100",
            50007,
            "tcp",
        );
        let result = router.route(&conn);
        println!("✓ test.jogiyw.sbs:443 → {}", result);
        assert_eq!(
            result, "direct",
            "Domain suffix jogiyw.sbs should go direct"
        );
    }

    // Test 9: Unknown domain with port 80 → omg
    {
        let conn = make_conn(None, "1.2.3.4", 80, "10.10.10.100", 50008, "tcp");
        let result = router.route(&conn);
        println!("✓ Unknown IP 1.2.3.4:80 → {}", result);
        assert_eq!(result, "omg", "Port 80 should go to omg");
    }

    // Test 10: Unknown domain, port 9090 → omg
    {
        let conn = make_conn(None, "1.2.3.4", 9090, "10.10.10.100", 50009, "tcp");
        let result = router.route(&conn);
        println!("✓ Unknown IP 1.2.3.4:9090 → {}", result);
        assert_eq!(result, "omg", "Port 9090 should go to omg");
    }

    // Test 11: Default (unknown port 12345) → direct
    {
        let conn = make_conn(None, "1.2.3.4", 12345, "10.10.10.100", 50010, "tcp");
        let result = router.route(&conn);
        println!("✓ Unknown IP 1.2.3.4:12345 → {}", result);
        assert_eq!(result, "direct", "Unknown port should fallback to direct");
    }

    println!("\n╔══════════════════════════════════════════╗");
    println!("║  All 11 routing tests passed with config.dae ║");
    println!("╚══════════════════════════════════════════╝");
}
