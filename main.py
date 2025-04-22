import os
import subprocess
from groq import Groq
from typing import List, Dict

from examples import examples, partial_examples

import re

GROQ_API_KEY = "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"
MODEL_NAME = "meta-llama/llama-4-maverick-17b-128e-instruct"
MAX_RETRIES = 3

client = Groq(api_key=GROQ_API_KEY)


def generate_prompt(intent: str, examples: List[Dict[str, str]], prev_errors: List[str] = None) -> str:
    """
    This function build a prompt that will be passed to Groq to generate a P4 configuration.
    :param intent: user's inputted intent
    :param examples: A list of intents: code pairs from the P4Lang Tutroial github to give the model
    an idea of how P4 code is structured. Format: [ {intent: "", code: ""}, {intent: "", code: ""}, ... ]
    :return: a prompt that will be passed to Groq to generate a P4 configuration.
    """

    warning = (
        "WARNING: Do NOT invent syntax. "
        "Use only valid P4 syntax—no invented keywords."
    )

    skeleton = (
        "P4 Program Structure:\n"
        "1. Include directives (`#include <core.p4>`, `#include <v1model.p4>`)\n"
        "2. Typedef declarations (e.g., `typedef bit<48> macAddr_t;`, `typedef bit<32> ip4Addr_t;`, `typedef bit<9> egressSpec_t;`)\n"
        "3. Header definitions\n"
        "4. Parser\n"
        "5. Table declarations\n"
        "6. Action definitions\n"
        "7. Ingress control (apply tables/actions here)\n"
        "8. Deparser\n"
        "9. Package instantiation\n\n"
        "Follow this exact order when writing your full program.\n\n"
    )

    prompt = (
            warning + skeleton +
            "You are a network configuration assistant. Translate the user's intent "
            "into a valid, compilable P4 program. Output ONLY the P4 code—no comments, "
            "no explanations, no markdown.\n\n"
    )

    prompt += "FULL EXAMPLES: Below are some FULL examples intents and corresponding valid full (complete program structure) P4 codes : \n"

    for example in examples:
        prompt += f"Intent: {example['intent']}\nCode:\n{example['code']}\n\n"

    prompt += f"PARTIAL EXAMPLES: below are partial building-block snippets (not full program structure). Do NOT repeat these verbatim \n"

    for partial_example in partial_examples:
        prompt += f"Intent: {partial_example['intent']}\nCode:\n{partial_example['code']}\n\n"

    if (prev_errors is not None) and (len(prev_errors) > 0):
        if prev_errors:
            prompt += "Previous compile errors detected. Please address each of the following numbered errors:\n"
            for idx, err in enumerate(prev_errors, 1):
                prompt += f"{idx}. {err}\n"
            prompt += "\nEnsure the new code fixes all listed errors before proceeding.\n\n"

    prompt += (
        "The above are for reference only. Now generate a new P4 program "
        f"for this intent:\nIntent: {intent}\nCode:\n"
    )

    # print(prompt)
    #
    # exit()
    return prompt


def generate_p4(intent: str, errors_list: List[str]):
    prompt = generate_prompt(intent, examples, errors_list)
    resp = client.chat.completions.create(
        messages=[{"role": "system", "content": prompt}],
        model=MODEL_NAME,
    )
    resp = resp.choices[0].message.content.strip()

    resp = re.sub(r'```(?:p4)?\s*\n?', '', resp)
    resp = re.sub(r'\n?```', '', resp)

    return resp


def validate_p4(filename: str):
    try:
        subprocess.run(["./validate.sh", filename],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True, ""
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode().strip()
        print(f"Compilation error:\n{err}")
        return False, err


def main():
    os.makedirs("p4_files", exist_ok=True)
    intent = input("Enter the networking intent: ").strip()
    attempt = 0
    errors_list = []

    while attempt < MAX_RETRIES:
        print(f"\n🔵 Attempt {attempt + 1}: Generating P4…")
        code = generate_p4(intent, errors_list)

        fname = f"generated_attempt_{attempt}.p4"
        path = os.path.join("p4_files", fname)
        with open(path, "w") as f:
            f.write(code)

        print("🔵 Validating generated code…")

        success, err = validate_p4(fname)

        if success:
            print(f"✅ Success! Valid P4 saved to {path}")
            return
        else:
            errors_list.append(err)
            print("❌ Compile failed. Retrying…")
            attempt += 1

    print("🚨 Failed after maximum retries.")


if __name__ == '__main__':
    main()
