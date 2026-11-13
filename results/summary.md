| variant | n | static | dynamic | combined |
|---|---|---|---|---|
| none | 25 | 25/25 | 25/25 | 25/25 |
| T_split | 25 | 25/25 | 25/25 | 25/25 |
| T_join | 25 | 25/25 | 25/25 | 25/25 |
| T_reverse | 25 | 25/25 | 25/25 | 25/25 |
| T_junk | 25 | 25/25 | 25/25 | 25/25 |
| T_var | 25 | 25/25 | 25/25 | 25/25 |
| T_dict | 25 | 25/25 | 25/25 | 25/25 |
| T_ns | 25 | 25/25 | 25/25 | 25/25 |
| T_macro | 25 | 25/25 | 25/25 | 25/25 |
| T_index | 25 | 25/25 | 25/25 | 25/25 |
| P_split | 25 | 25/25 | 25/25 | 25/25 |
| P_index | 25 | 25/25 | 25/25 | 25/25 |
| P_base64 | 23 | 23/23 | 23/23 | 23/23 |
| P_zwsp | 23 | 23/23 | 23/23 | 23/23 |
| P_homoglyph | 23 | 23/23 | 23/23 | 23/23 |
| TP_index | 25 | 0/25 | 25/25 | 25/25 |
| TP_mixed | 23 | 23/23 | 23/23 | 23/23 |
| N_count | 23 | 15/23 | 23/23 | 23/23 |

Benign templates (flagged = malicious or suspicious):
- neg-fujitsu n=13 static: {'malicious': 0, 'suspicious': 0, 'clean': 13, 'error': 0}  flagged=[]
- neg-fujitsu n=13 dynamic: {'malicious': 0, 'suspicious': 0, 'clean': 13, 'error': 0}  flagged=[]
- neg-fujitsu n=13 combined: {'malicious': 0, 'suspicious': 0, 'clean': 13, 'error': 0}  flagged=[]
- neg-real n=74 static: {'malicious': 0, 'suspicious': 4, 'clean': 70, 'error': 0}  flagged=['IFM-K2-Horizon.jinja', 'inclusionai-ling-3.0-flash.jinja', 'muse-spark.jinja', 'openbmb-MiniCPM5-1B.jinja']
- neg-real n=74 dynamic: {'malicious': 0, 'suspicious': 0, 'clean': 72, 'error': 2}  flagged=[]
- neg-real n=74 combined: {'malicious': 0, 'suspicious': 0, 'clean': 74, 'error': 0}  flagged=[]

Totals over valid positive variants: static 407/440, dynamic 440/440, combined 440/440
Skipped (identical to base template, not poisoned): scenario_a/command_r.jinja