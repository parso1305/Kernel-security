# StreamAttest Phase 1

## How to build
```bash
make
```

## How to run
1. Start nginx:
```bash
sudo /opt/nginx/sbin/nginx
```

2. Run loader:
```bash
sudo ./user/loader
```

3. Generate traffic:
```bash
wrk -t2 -c20 http://127.0.0.1
```

## Expected output
```
Epoch 1 → Signal 1
Epoch 2 → Signal 1
...
```
