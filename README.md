# Eonark GPU Version

# Getting Started
This section describes **every step required to run EONARK-GPU on a fresh machine**

## 0. Hardware & OS Assumptions

Linux (Ubuntu 20.04 / 22.04 / 24.04 recommended)

NVIDIA GPU (tested on RTX 4090)

## 1. Clone the Repository

Clone the repository and enter the project directory:

```bash
git clone https://github.com/YolaYing/eonark-gpu.git
cd eonark-gpu
```

## 2. Go Dependencies

Pull all Go dependencies (including `icicle-gnark`) into the local module cache:

```bash
go mod tidy
```

## 6. Build ICICLE Native Libraries (BLS12-381)

> **Important**  
> `icicle-gnark` requires building native C++ libraries manually before it can be used by Go.

---

### 6.1 Navigate to ICICLE source directory

```bash
cd $(go env GOMODCACHE)/github.com/ingonyama-zk/icicle-gnark/v3@*/wrappers/golang
```

### 6.2 Build ICICLE for BLS12-381

```bash
chmod +x build.sh
./build.sh -curve=bls12_381
```

### 6.3 Verify generated libraries

Frontend libraries (must exist):
```bash
/usr/local/lib/
├── libicicle_curve_bls12_381.so
├── libicicle_field_bls12_381.so
└── libicicle_device.so
```
Backend CUDA libraries (must exist):
```bash
/usr/local/lib/backend/
├── libicicle_backend_cuda_curve_bls12_381.so
├── libicicle_backend_cuda_field_bls12_381.so
└── libicicle_backend_cuda_device.so
```

## 7. Environment Variables

You **must** export the following environment variables so that Go + CGO can correctly locate ICICLE and CUDA libraries.

---

### 7.1 Recommended `.envrc` (using direnv)

Create a `.envrc` file in the repository root:

```bash
# ICICLE
export ICICLE_LIB="$HOME/.local/icicle/lib"
export LD_LIBRARY_PATH="$ICICLE_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export CGO_LDFLAGS="-L$ICICLE_LIB -Wl,-rpath,$ICICLE_LIB ${CGO_LDFLAGS}"
export LIBRARY_PATH="$ICICLE_LIB${LIBRARY_PATH:+:$LIBRARY_PATH}"
export ICICLE_BACKEND_INSTALL_DIR="$HOME/.local/icicle/lib/backend"
export ICICLE_BACKEND=cuda

# CUDA
export CUDA_HOME="/usr/local/cuda-12.8"
export PATH="$CUDA_HOME/bin:$PATH"
export LD_LIBRARY_PATH="$CUDA_HOME/lib64:$CUDA_HOME/extras/CUPTI/lib64:$LD_LIBRARY_PATH"
```
Enable the environment:
```bash
direnv allow
```

## 8. Build & Run Tests (GPU)
Run the recursion circuit test with GPU enabled:
```bash
go test -tags icicle ./circuits/recursion \
  -run Test_Recursion \
  -count=1 \
  -v
```

Expected output includes logs similar to:
```bash
[INFO] ICICLE backend loaded from ...
[TIMING] ...
=== RUN   Test_Recursion
--- PASS: Test_Recursion
```