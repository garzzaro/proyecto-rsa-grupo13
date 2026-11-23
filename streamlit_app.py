"""Interfaz web adicional. Los archivos de original/ se conservan intactos."""
from pathlib import Path
import sys

import streamlit as st

ORIGINAL = Path(__file__).resolve().parent / "original"
sys.path.insert(0, str(ORIGINAL))
from crypto_rsa import (
    encriptar_mensaje, desencriptar_mensaje, validar_parametros_rsa,
    generar_pareja_aleatoria_libre, sugerir_parametros_rsa,
    obtener_exponentes_compatibles, desglosar_calculos_paso_a_paso,
)

st.set_page_config(page_title="Criptografía RSA · Grupo 13", page_icon="🔐", layout="wide")


def aplicar(sugerencia):
    for nombre in ("p", "q"):
        st.session_state[nombre] = sugerencia[nombre]
    st.session_state.e = sugerencia["e_recomendado"]
    st.session_state.pop("enc", None)
    st.session_state.pop("dec", None)


def transferir():
    resultado = st.session_state.enc
    st.session_state.cifrado = resultado["mensaje_cifrado_C"]
    st.session_state.longitud = resultado["L"]


for clave, valor in {"p": 367, "q": 373, "e": 17, "cifrado": "026054 123875", "longitud": 3}.items():
    st.session_state.setdefault(clave, valor)

st.title("🔐 Criptografía RSA")
st.caption("MM2015 · Matemática Discreta 1 · Grupo No. 13")

with st.sidebar:
    st.header("Parámetros RSA")
    st.number_input("Primo p", min_value=2, max_value=999999, step=1, key="p")
    st.number_input("Primo q", min_value=2, max_value=999999, step=1, key="q")
    st.number_input("Exponente público e", min_value=2, max_value=2147483647, step=1, key="e")
    st.button("Cargar caso de referencia", on_click=aplicar, args=(sugerir_parametros_rsa(),), use_container_width=True)
    st.caption("La misma lógica matemática del proyecto original, ahora en el navegador.")

p, q, e = (int(st.session_state[k]) for k in ("p", "q", "e"))
valido = False
try:
    n, phi, d = validar_parametros_rsa(p, q, e)
    valido = True
    columnas = st.columns(4)
    for col, etiqueta, valor in zip(columnas, ["n = p × q", "φ(n)", "Clave pública (e, n)", "Clave privada (d, n)"], [n, phi, f"({e}, {n})", f"({d}, {n})"]):
        col.metric(etiqueta, str(valor))
except (ValueError, TypeError) as error:
    st.error(str(error))

enc, dec, asistente, desglose, ayuda, codigo = st.tabs([
    "Encriptar", "Desencriptar", "Asistente de primos", "Desglose matemático", "Instrucciones", "Código original"
])

with enc:
    st.subheader("Encriptar mensaje")
    with st.form("encriptacion"):
        mensaje = st.text_area("Mensaje original M", value="RSA", height=120, max_chars=10000)
        st.caption("Caracteres ASCII imprimibles (32–126). Se conservan los espacios. Máximo 10,000 caracteres por operación web.")
        ejecutar = st.form_submit_button("Encriptar", disabled=not valido, use_container_width=True)
    if ejecutar:
        try:
            st.session_state.enc = encriptar_mensaje(mensaje, p, q, e)
        except (ValueError, TypeError) as error:
            st.session_state.pop("enc", None)
            st.error(str(error))
    if "enc" in st.session_state:
        resultado = st.session_state.enc
        st.caption(f"Resultado con p={resultado['p']}, q={resultado['q']}, e={resultado['e']}")
        st.code(resultado["mensaje_cifrado_C"], language=None)
        st.write(f"Longitud original L = {resultado['L']} · Relleno añadido: {'sí' if resultado['hubo_relleno'] else 'no'}")
        st.dataframe(resultado["detalle_pasos"], use_container_width=True, hide_index=True)
        st.button("Transferir a Desencriptar", on_click=transferir)
        st.download_button("Descargar cifrado", resultado["mensaje_cifrado_C"], "cifrado_RSA.txt")

with dec:
    st.subheader("Desencriptar mensaje")
    with st.form("desencriptacion"):
        cifrado = st.text_area("Mensaje cifrado C", key="cifrado", height=120, max_chars=35000)
        longitud = st.number_input("Longitud original L", min_value=1, max_value=10000, step=1, key="longitud")
        ejecutar_dec = st.form_submit_button("Desencriptar", disabled=not valido, use_container_width=True)
    if ejecutar_dec:
        try:
            st.session_state.dec = desencriptar_mensaje(cifrado, int(longitud), p, q, e)
        except (ValueError, TypeError) as error:
            st.session_state.pop("dec", None)
            st.error(str(error))
    if "dec" in st.session_state:
        resultado = st.session_state.dec
        st.caption(f"Resultado con p={resultado['p']}, q={resultado['q']}, e={resultado['e']}")
        st.code(resultado["mensaje_recuperado"], language=None)
        st.dataframe(resultado["detalle_pasos"], use_container_width=True, hide_index=True)
        st.download_button("Descargar mensaje recuperado", resultado["mensaje_recuperado"], "mensaje_RSA.txt")

with asistente:
    st.subheader("Asistente de parámetros")
    categorias = {"Todos": "todos", "Módulo pequeño": "pequeno", "Módulo mediano": "mediano", "Módulo grande": "grande", "Primos cercanos": "cercanos", "Primos asimétricos": "asimetricos"}
    categoria = st.selectbox("Tipo de pareja", list(categorias))
    if st.button("Generar pareja aleatoria"):
        st.session_state.sugerencia = generar_pareja_aleatoria_libre(categorias[categoria])
    if st.button("Siguiente sugerencia"):
        st.session_state.indice = st.session_state.get("indice", 0) + 1
        st.session_state.sugerencia = sugerir_parametros_rsa(categorias[categoria], st.session_state.indice)
    if "sugerencia" in st.session_state:
        sug = st.session_state.sugerencia
        st.write(sug["descripcion"])
        st.json(sug)
        st.button("Aplicar estos parámetros", on_click=aplicar, args=(sug,))
    if valido:
        st.write("Exponentes compatibles con los parámetros actuales:")
        st.code(", ".join(map(str, obtener_exponentes_compatibles(phi))), language=None)

with desglose:
    st.subheader("Cálculos paso a paso")
    if valido:
        detalle = desglosar_calculos_paso_a_paso(p, q, e)
        st.write(f"p = {p} y q = {q} son primos distintos.")
        st.latex(rf"n = {p}\times {q} = {n}")
        st.latex(rf"\varphi(n) = ({p}-1)({q}-1) = {phi}")
        st.markdown("**Algoritmo de Euclides**")
        for paso in detalle["pasos_euclides"]:
            st.code(paso["ecuacion"], language=None)
        st.markdown("**Bézout matricial**")
        st.dataframe(detalle["pasos_bezout"], use_container_width=True, hide_index=True)
        st.code(detalle["ecuacion_bezout"], language=None)
        st.write(f"Inverso modular d = {detalle['d_calculado']}")
        st.success(detalle["verificacion_modular"])
    else:
        st.info("Introduce parámetros válidos para ver el desglose.")

with ayuda:
    st.subheader("Cómo utilizar el proyecto")
    st.markdown("1. Elige p, q y e en la barra lateral, o utiliza el asistente.\n2. En **Encriptar**, escribe el mensaje y conserva C y L.\n3. En **Desencriptar**, utiliza el mismo p, q y e, introduce C y L.\n4. Consulta el desglose matemático para explicar cada cálculo.")
    st.info("Caso de referencia: M = RSA; p = 367; q = 373; e = 17; L = 3; C = 026054 123875.")
    st.caption("Proyecto didáctico de RSA con los límites y validaciones originales.")
    with st.expander("Documento original completo"):
        st.markdown((ORIGINAL / "README.md").read_text(encoding="utf-8"))
    video = ORIGINAL / "VIDEO DEMOSTRATIVO.mp4"
    if video.exists():
        with st.expander("Video demostrativo original"):
            st.video(str(video))

with codigo:
    st.subheader("Archivos originales intactos")
    archivo = st.selectbox("Consultar código", ["crypto_rsa.py", "gui.py", "main.py", "test_rsa.py", "requirements.txt"])
    contenido = (ORIGINAL / archivo).read_bytes()
    st.code(contenido.decode("utf-8"), language="python" if archivo.endswith(".py") else None)
    st.download_button("Descargar archivo original", contenido, archivo)
