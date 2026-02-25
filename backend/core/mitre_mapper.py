MITRE_RULE_MAP = {
    "100100": ("Execution", "Command-Line Interface", "T1059"),
    "100200": ("Persistence", "Registry Run Keys", "T1547")
}

class MitreMapper:

    def map_alert(self, alert):

        rule_id = alert.get("rule", {}).get("id")

        if rule_id in MITRE_RULE_MAP:
            tactic, tech, tid = MITRE_RULE_MAP[rule_id]
            return {
                "tactic": tactic,
                "technique": tech,
                "technique_id": tid
            }
