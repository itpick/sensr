| router | rules | method | proto | total s | commit s | add s | apply s | n |
|---|---|---|---|---|---|---|---|---|
| opn | None | None | None | 0.358 (0.335–0.486) | n/a | 0.061 (0.053–0.194) | 0.292 (0.275–0.358) | 5 |
| opnL | None | None | None | 1.584 (1.321–1.732) | n/a | 0.527 (0.480–0.733) | 0.900 (0.794–1.196) | 5 |
| nixr | 50 | rust prototype POST /api/rules | None | 0.015 (0.012–0.018) | n/a | n/a | 0.012 (0.010–0.014) | 5 |
| nixr | 1000 | rust prototype POST /api/rules | None | 0.141 (0.105–0.170) | n/a | n/a | 0.081 (0.071–0.116) | 5 |
| nixr | 10000 | rust prototype POST /api/rules | None | 0.716 (0.669–0.945) | n/a | n/a | 0.395 (0.387–0.416) | 5 |
| vyos | None | vbash configure/set/commit | None | 2.231 (2.200–2.971) | 1.855 (1.823–2.055) | n/a | n/a | 5 |
| obsd | None | pfctl -f (whole ruleset) | None | 0.015 (0.015–0.018) | n/a | n/a | n/a | 5 |
| obsdL | None | pfctl -f (whole ruleset) | None | 0.062 (0.061–0.063) | n/a | n/a | n/a | 5 |
| nixr | 50 | rust prototype POST /api/rules | /root/sensr-proto-stream | 0.016 (0.013–0.017) | n/a | n/a | 0.011 (0.009–0.012) | 5 |
| nixr | 1000 | rust prototype POST /api/rules | /root/sensr-proto-stream | 0.124 (0.123–0.130) | n/a | n/a | 0.071 (0.070–0.073) | 5 |
| nixr | 10000 | rust prototype POST /api/rules | /root/sensr-proto-stream | 0.757 (0.750–0.758) | n/a | n/a | 0.366 (0.361–0.372) | 5 |
| vyosL | None | vbash configure/set/commit | None | 26.410 (26.386–27.008) | 25.967 (25.911–26.041) | n/a | n/a | 5 |
