| router | size | method | proto | total s | commit s | render s | apply s | n |
|---|---|---|---|---|---|---|---|---|
| opn | 1k | None | None | 0.859 (0.739–1.110) | n/a | n/a | n/a | 5 |
| opn | 10k | None | None | 1.054 (0.853–1.153) | n/a | n/a | n/a | 5 |
| nixr | 1k | rust prototype: render JSON + nft -j -f | None | 0.015 (0.012–0.016) | n/a | 0.000 (0.000–0.001) | 0.014 (0.011–0.016) | 5 |
| nixr | 10k | rust prototype: render JSON + nft -j -f | None | 0.054 (0.044–0.055) | n/a | 0.006 (0.006–0.006) | 0.048 (0.039–0.049) | 5 |
| nixr | 100k | rust prototype: render JSON + nft -j -f | None | 0.686 (0.584–0.701) | n/a | 0.079 (0.077–0.081) | 0.608 (0.504–0.622) | 5 |
| vyos | 1k | vbash delete+set network-group + commit | None | 41.733 | 4.992 | n/a | n/a | 1 |
| vyos | 10k | vbash delete+set network-group + commit | None | 508.250 | 32.478 | n/a | n/a | 1 |
| opn | 100k | None | None | 1.080 (1.032–1.700) | n/a | n/a | n/a | 5 |
| nixr | 1k | rust prototype: render JSON + nft -j -f | /root/sensr-proto-stream | 0.017 (0.013–0.019) | n/a | 0.002 (0.001–0.002) | 0.015 (0.011–0.017) | 5 |
| nixr | 10k | rust prototype: render JSON + nft -j -f | /root/sensr-proto-stream | 0.050 (0.049–0.054) | n/a | 0.009 (0.009–0.009) | 0.041 (0.040–0.044) | 5 |
| nixr | 100k | rust prototype: render JSON + nft -j -f | /root/sensr-proto-stream | 0.651 (0.586–0.663) | n/a | 0.114 (0.114–0.117) | 0.534 (0.472–0.549) | 5 |
