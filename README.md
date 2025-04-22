# Intent-Based P4 Configuration Generation

This project implements a system to automatically generate valid P4 network configurations from user-provided natural language intents.

A large language model (LLM) generates P4 programs from a structured prompt, and each generated output is validated using the P4C compiler. If the initial output fails, compiler errors are captured, fed back into the next prompt, and the model retries until successful compilation or maximum retries are exhausted.

## Project Structure

- `main.py` &mdash; Main script handling user input, prompt construction, LLM generation, and validation loop.
- `examples.py` &mdash; Contains full and partial few-shot examples used for conditioning the LLM.
- `validate.sh` &mdash; Script for compiling generated `.p4` files inside a P4C Docker container.

## Requirements

- Linux or WSL (Windows Subsystem for Linux)
- Python 3.10+ (lower versions are likely to work fine)
- Docker installed and running
- [Groq API Key](https://console.groq.com/) (Mine is hardcoded in the code for the sake of testing in main.py)

## Setup

1. Clone the repository:

```bash
git clone https://github.com/IlliaNasiri/IBN.git
cd IBN
```

2. Install Python dependencies:

```bash
pip install groq
```

3. Install Docker (if not already installed):

### On Ubuntu/WSL:

```bash
sudo apt-get update
sudo apt-get install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
```

4. Ensure Docker is running. Verify with:

```bash
docker --version
```

5. Set your Groq API key and mofigy variable ```GROQ_API_KEY = ``` in `main.py`

6. [OPTIONAL] Pull the P4C Docker image:

```bash
docker pull p4lang/p4c
```

## Usage

Run the main script:

```bash
python main.py
```

You will be prompted to enter a natural language networking intent.
The script will attempt to generate a compilable P4 program based on your input, retrying automatically if validation fails.

## Method Summary

- **Few-shot learning** is used by embedding curated full and partial P4 examples directly inside the prompt.
- **Large context model** (`meta-llama/llama-4-maverick`) is used to accommodate extensive examples.
- **Validation loop** captures compiler errors and feeds them into the next generation attempt.
- **Maximum retries** per intent are set to 3.

## Example Intents

- "Forward packets based on the destination IP address."
- "Drop packets arriving on port 3."
- "Perform source NAT, replacing the source IP with 192.168.1.1."
- "Load balance incoming traffic across 4 ports based on source IP."

