import os
from typing import Dict, Any, Optional
from openai import OpenAI

# Use the same client from AgentsDS
client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"], # api_key=os.getenv("DEEPSEEK_API_KEY"),
    base_url=os.environ["OPENAI_BASE_URL"] # base_url="https://api.deepseek.com"
)

# Base LLM caller

    
def _deepseek_base_call(
    prompt: str,
    *,
    system_prompt: str,
    model: str = "deepseek-chat",
    max_tokens: int = 300,
    temperature: float = 0.0,
) -> str:
    if prompt is None:
        return "ERROR: PROMPT_IS_NONE"
    print(f"[DeepSeek:{model}] Processing: {prompt[:120]!r} ...")

    try:
        response = client.chat.completions.create(
                model = model,
             messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
                        ],
            max_tokens  = max_tokens,
            temperature = temperature,
        )

        content = response.choices[0].message.content
        if content is None:
            return "ERROR: EMPTY_RESPONSE"

        content = content.strip()
        if not content:
            return "ERROR: EMPTY_RESPONSE"

        print("[DeepSeek RAW OUTPUT]:", repr(content))
        return content

    except Exception as e:
        return f"ERROR: API_FAILURE: {str(e)}"

def deepseek_acl_resolver(prompt: str, task: str) -> str:
    task = (task or "").strip().lower()

    if task == "interface":
        system_prompt = """
            You are a network ACL placement resolver.
            
            Determine the ingress interface on the chosen device for the described traffic.
            
            Output rules:
            - Return exactly one interface name only.
            - No explanation.
            - No punctuation.
            - No markdown.
            - Examples: g0/0, g0/1, fa0/0
            - If not derivable from the provided text, return exactly: None
            """.strip()
        max_tokens = 20

    elif task == "direction":
        system_prompt = """
            You are a network ACL placement resolver.
            
            Determine whether the ACL should be applied inbound or outbound on the specified interface.
            
            Output rules:
            - Return exactly one token only: in or out
            - No explanation.
            - No punctuation.
            - No markdown.
            - If not derivable from the provided text, return exactly: None
            """.strip()
        max_tokens = 10

    elif task == "acl_name":
        system_prompt = """
            You are reading Cisco IOS router configuration.
            
            Determine whether an ACL is already applied on the specified interface and direction.
            
            Output rules:
            - Return exactly one token only:
              - the ACL name, or
              - None
            - No explanation.
            - No punctuation.
            - No markdown.
            """.strip()
        max_tokens = 20

    else:
        return "ERROR: UNKNOWN_RESOLVER_TASK"

    return _deepseek_base_call(
        prompt,
        system_prompt=system_prompt,
        model="deepseek-chat",
        max_tokens=max_tokens,
        temperature=0.0,
    )

def deepseek_acl_generator(prompt: str, mode: str) -> str:
    mode = (mode or "generate").strip().lower()

    if mode == "generate":
        system_prompt = """
        You are a Cisco IOS ACL configuration renderer.
        
        Output only valid Cisco IOS configuration commands.
        Do not explain.
        Do not comment.
        Do not add markdown fences.
        Do not guess missing values.
        Do not add extra ACL lines.
        If the prompt says to return a specific ERROR line, return that exact line only.
        """.strip()
        max_tokens = 260

    elif mode == "applyonintf":
        system_prompt = """
        You are a Cisco IOS ACL application renderer.
        
        Output only valid Cisco IOS configuration commands.
        Do not explain.
        Do not comment.
        Do not add markdown fences.
        Do not redefine the ACL.
        Do not generate ACL rules.
        Only apply the existing ACL to the provided interface and direction.
        If the prompt says to return a specific ERROR line, return that exact line only.
        """.strip()
        max_tokens = 120

    elif mode == "fix_attachment":
        system_prompt = """
        You are a Cisco IOS configuration snippet rewriter.
        
        Fix only ACL attachment.
        Do not change ACL rule semantics.
        Do not rename the ACL.
        Do not add explanations or markdown.
        Return only the final corrected configuration snippet.
        If the prompt says to return a specific ERROR line, return that exact line only.
        """.strip()
        max_tokens = 400

    elif mode == "fix_order":
        system_prompt = """
        You are a Cisco IOS ACL line reordering engine.
        
        Reorder ACL lines only.
        Do not add, remove, edit, or rename any ACL line.
        Do not modify the interface stanza.
        Do not add explanations or markdown.
        Return only the corrected ACL block and unchanged interface stanza.
        If the prompt says to return a specific ERROR line, return that exact line only.
        """.strip()
        max_tokens = 400

    else:
        return "ERROR: UNKNOWN_ACL_GENERATOR_MODE"

    return _deepseek_base_call(
        prompt,
        system_prompt=system_prompt,
        model="deepseek-coder",
        max_tokens=max_tokens,
        temperature=0.0,
    )