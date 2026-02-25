import os
from groq import Groq
import logging

logger = logging.getLogger(__name__)

#load env
from dotenv import load_dotenv
load_dotenv()

# Configuración
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
client = Groq(api_key=GROQ_API_KEY)

async def call_groq_api(prompt: str, system_prompt: str = "") -> str:
    """
    Obtiene la respuesta completa. 
    Compatible con tu lógica de parse_and_apply_action en Render.
    """
    try:
        # Nota: Asegúrate de usar un modelo válido como "qwen-2.5-7b-instruct"
        completion = client.chat.completions.create(
            model="qwen/qwen3-32b", 
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.6,
            max_tokens=4096,
        )
        return completion.choices[0].message.content
    except Exception as e:
        logger.error(f"Error en Groq API: {e}")
        return f"Error: No pude conectar con el motor de IA. {str(e)}"

async def call_groq_stream(prompt: str, system_prompt: str = ""):
    """
    Versión para streaming (palabra por palabra).
    """
    try:
        stream = client.chat.completions.create(
            model="qwen/qwen3-32b",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.6,
            stream=True,
        )
        for chunk in stream:
            content = chunk.choices[0].delta.content
            if content:
                yield content
    except Exception as e:
        logger.error(f"Error en Groq Stream: {e}")
        yield f"Error de conexión: {str(e)}"