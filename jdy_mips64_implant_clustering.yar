/*
    JDY Botnet - MIPS64 implant clustering rule
    ------------------------------------------------------------------
    Purpose:  CLUSTERING / sample-discovery rule for the JDY reconnaissance
              implant (China-nexus, Volt Typhoon / KV lineage, MITRE G1017).
              Intended for corpus retrohunt (e.g. MalwareBazaar / YARAify /
              VT Intelligence) to surface sibling samples - NOT a host
              deployment / EDR detection rule.

    Anchors:  - nested OpenSSL build path  /usr/local/openssl/1.0.2u/mips64/
                (the nested version/arch directory shape is the discriminator;
                 the flat/hyphen form openssl-1.0.2u is commodity)
              - version string 1.8.3.9
              - the SYN ISN seed 0x3251d2d (little- and big-endian byte forms)
              Gated on ELF + MIPS big-endian so it cannot match unrelated
              x86 / PE artifacts.

    NOTE on the certificate serial: the jdyfj cert serial is NOT included as a
    condition. The certificate is served by the relay (server side); it is NOT
    embedded in the implant. Including it would zero out every implant match.
    The cert/network pivot lives in jdy_network_cert_notes.md instead.

    Reference: https://github.com/yankywilson/jdy-tasking-decryption
    Author:    JDY Investigation
*/

import "elf"

rule JDY_MIPS64_implant_clustering
{
    meta:
        description = "JDY reconnaissance implant - MIPS64 BE clustering rule (sibling discovery)"
        author      = "JDY Investigation"
        date        = "2026-06-24"
        reference   = "https://github.com/yankywilson/jdy-tasking-decryption"
        family      = "JDY"
        actor       = "Volt Typhoon ecosystem (G1017)"
        purpose     = "clustering / retrohunt - not deployment detection"
        tlp         = "CLEAR"

    strings:
        // Primary anchor: nested build path (highly distinctive)
        $build      = "/usr/local/openssl/1.0.2u/mips64/" ascii

        // Supporting: version string
        $ver        = "1.8.3.9" ascii

        // Supporting: dispatch API surface
        $disp1      = "/dispatch_service/v2/probe_task" ascii
        $disp2      = "/dispatch_service/v2/probe_status" ascii
        $disp3      = "/dispatch_service/v2/test" ascii
        $dmap       = "/dispatch/v2/dmap/" ascii

        // Supporting: tasking key (raw ASCII key material in the binary)
        $key        = "bdb718bdf47cbcde" ascii

        // Supporting: SYN ISN seed 0x3251d2d as immediate bytes (both orders)
        $isn_be     = { 03 25 1d 2d }
        $isn_le     = { 2d 1d 25 03 }

    condition:
        // Must be an ELF for MIPS, big-endian
        uint32be(0) == 0x7f454c46
        and elf.machine == elf.EM_MIPS
        and elf.type == elf.ET_EXEC
        and (
            // strongest single anchor
            $build
            or
            // or a corroborated combination if the path was stripped/obfuscated
            ( $ver and 2 of ($disp1, $disp2, $disp3, $dmap, $key) )
            or
            ( $key and 1 of ($isn_be, $isn_le) and 1 of ($disp1, $disp2, $disp3, $dmap) )
        )
}
