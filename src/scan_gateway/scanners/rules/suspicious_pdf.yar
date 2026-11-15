/*
 * Hand-written, bundled in this repo rather than pulling in a third-party
 * community ruleset sight-unseen (licensing/trust/size concerns for an
 * external signature file). Intentionally small -- this backs
 * LocalHeuristicScanner, the built-in fallback scanner, not a replacement
 * for a real scanner plugin's (e.g. ClamAV's) much larger signature
 * database.
 */

rule EICAR_Test_String
{
    meta:
        description = "Standard EICAR antivirus test string -- not a real virus, used to verify the scanning pipeline end to end."
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PDF_JS_Obfuscation
{
    meta:
        description = "Common obfuscation patterns seen in malicious PDF embedded JavaScript (heap-spray prep, dynamic eval, string unescaping) -- heuristic, not a signature match."
    strings:
        $unescape = "unescape(" nocase
        $eval = /eval\s*\(/ nocase
        $heapspray = /%u[0-9a-f]{4}%u[0-9a-f]{4}/ nocase
    condition:
        2 of them
}
