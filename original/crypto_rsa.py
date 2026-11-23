"""
Proyecto de Criptografía RSA - Matemática Discreta 1 (MM2015)
Módulo Central de Lógica Criptográfica y Matemática Modular

Este archivo contiene la implementación completa y autónoma de los algoritmos
requeridos por el proyecto, sin utilizar funciones prohibidas como math.gcd,
pow(base, exp, mod) con 3 argumentos, pow(e, -1, phi) ni librerías externas de criptografía.
"""

from typing import Tuple, List, Dict, Any, Optional


# ==============================================================================
# 1. ALGORITMOS MATEMÁTICOS PRINCIPALES
# ==============================================================================

def es_primo(num: int) -> bool:
    """
    Verifica la primalidad de un número entero positivo mediante
    división por tentativa optimizada (6k +/- 1).
    """
    if not isinstance(num, int):
        return False
    if num <= 1:
        return False
    if num in (2, 3):
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False

    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True


def mcd_euclides(a: int, b: int) -> int:
    """
    Calcula el Máximo Común Divisor entre dos enteros mediante el
    algoritmo tradicional de Euclides por divisiones sucesivas.
    """
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("Los argumentos del MCD deben ser enteros.")
    
    a_abs, b_abs = abs(a), abs(b)
    while b_abs != 0:
        a_abs, b_abs = b_abs, a_abs % b_abs
    return a_abs


def bezout_matricial(a: int, b: int) -> Tuple[int, int]:
    """
    Aplica el Algoritmo Extendido de Euclides mediante la formulación matricial
    trabajada en clase para encontrar los coeficientes de Bézout (s, t) tales
    que: a * s + b * t = MCD(a, b).
    """
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("Los argumentos para Bézout deben ser enteros.")
    if a <= 0 or b <= 0:
        raise ValueError("Los argumentos para Bézout deben ser enteros positivos.")

    # Matriz identidad inicial para el seguimiento de coeficientes
    m = [[1, 0], [0, 1]]
    r0, r1 = a, b

    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 % r1
        # Actualización matricial
        m = [m[1], [m[0][0] - q * m[1][0], m[0][1] - q * m[1][1]]]

    return (m[0][0], m[0][1])


def inverso_modular(e: int, phi: int) -> int:
    """
    Calcula el inverso modular d tal que:
    e * d ≡ 1 (mod phi) con 1 <= d < phi.
    
    Utiliza los coeficientes de Bézout de la implementación matricial propia.
    """
    if not isinstance(e, int) or not isinstance(phi, int):
        raise TypeError("Los valores para el inverso modular deben ser enteros.")
    if phi <= 1:
        raise ValueError("El módulo phi debe ser mayor que 1.")
    
    g = mcd_euclides(e, phi)
    if g != 1:
        raise ValueError(f"No existe inverso modular: MCD({e}, {phi}) = {g} != 1.")

    s, _ = bezout_matricial(e, phi)
    d = s % phi
    if d < 1:
        d += phi
    return d


def exponenciacion_modular(base: int, exp: int, mod: int) -> int:
    """
    Calcula (base^exp) mod mod mediante exponenciación binaria (cuadrados repetidos),
    reduciendo en cada iteración bajo el módulo mod para evitar números gigantescos.
    
    No utiliza pow(base, exp, mod).
    """
    if not isinstance(base, int) or not isinstance(exp, int) or not isinstance(mod, int):
        raise TypeError("Todos los argumentos de exponenciación deben ser enteros.")
    if mod < 2:
        raise ValueError("El módulo debe ser mayor o igual a 2.")
    if exp < 0:
        raise ValueError("El exponente no puede ser negativo.")

    resultado = 1
    base_actual = base % mod
    potencia = exp

    while potencia > 0:
        # Si el bit menos significativo es 1, multiplicar
        if potencia % 2 == 1:
            resultado = (resultado * base_actual) % mod
        base_actual = (base_actual * base_actual) % mod
        potencia //= 2

    return resultado


# ==============================================================================
# 2. VALIDACIÓN DE PARÁMETROS Y CARACTERES
# ==============================================================================

def validar_caracteres_ascii(mensaje: str) -> None:
    """
    Verifica que todos los caracteres pertenezcan al rango ASCII imprimible [32, 126].
    Lanza ValueError si encuentra algún carácter prohibido.
    """
    for idx, c in enumerate(mensaje):
        codigo = ord(c)
        if codigo < 32 or codigo > 126:
            raise ValueError(
                f"Carácter no admitido '{c}' (código ASCII {codigo}) en la posición {idx + 1}. "
                f"Solo se permiten caracteres ASCII imprimibles entre 32 y 126."
            )


def validar_parametros_rsa(p: int, q: int, e: int) -> Tuple[int, int, int]:
    """
    Verifica las condiciones matemáticas de la especificación:
    - p y q deben ser enteros primos distintos.
    - 126126 < n < 1000000, donde n = p * q.
    - phi = (p - 1) * (q - 1).
    - e > 1 y MCD(e, phi) == 1.
    
    Retorna la tupla (n, phi, d).
    """
    if not isinstance(p, int) or not isinstance(q, int) or not isinstance(e, int):
        raise TypeError("Los valores p, q y e deben ser enteros.")

    if p == q:
        raise ValueError("Los valores p y q deben ser primos distintos.")

    if not es_primo(p):
        raise ValueError(f"El valor p = {p} no es un número primo.")

    if not es_primo(q):
        raise ValueError(f"El valor q = {q} no es un número primo.")

    n = p * q
    if n <= 126126:
        raise ValueError(
            f"El módulo n = {n} es demasiado pequeño (debe ser mayor a 126126 para admitir todos los caracteres)."
        )
    if n >= 1000000:
        raise ValueError(
            f"El módulo n = {n} excede el límite permitido (debe ser estrictamente menor a 1,000,000)."
        )

    phi = (p - 1) * (q - 1)

    if e <= 1:
        raise ValueError(f"El exponente público e = {e} debe ser mayor que 1.")

    g = mcd_euclides(e, phi)
    if g != 1:
        raise ValueError(
            f"El exponente e = {e} no es coprimo con phi = {phi} (MCD(e, phi) = {g})."
        )

    d = inverso_modular(e, phi)
    return (n, phi, d)


# ==============================================================================
# 3. PROCESO DE ENCRIPTACIÓN
# ==============================================================================

def encriptar_mensaje(mensaje: str, p: int, q: int, e: int) -> Dict[str, Any]:
    """
    Ejecuta el protocolo completo de encriptación RSA según las especificaciones:
    1. Valida mensaje M, p, q y e.
    2. Registra longitud original L.
    3. Si L es impar, agrega exactamente un espacio al final (' ', ASCII 32).
    4. Separa en parejas de caracteres, concatenando sus códigos de 3 dígitos -> bloque m.
    5. Cifra cada bloque: c = m^e (mod n).
    6. Formatea cada c con exactamente 6 dígitos (ceros a la izquierda).
    
    Retorna un diccionario con los resultados y el detalle de cada paso.
    """
    validar_caracteres_ascii(mensaje)
    n, phi, d = validar_parametros_rsa(p, q, e)

    L = len(mensaje)
    hubo_relleno = (L % 2 != 0)
    mensaje_procesado = mensaje + " " if hubo_relleno else mensaje

    bloques_detalle = []
    bloques_cifrados = []

    # Procesar parejas de dos caracteres
    for i in range(0, len(mensaje_procesado), 2):
        c1 = mensaje_procesado[i]
        c2 = mensaje_procesado[i + 1]

        cod1 = ord(c1)
        cod2 = ord(c2)

        # Cada carácter con exactamente 3 dígitos
        str_cod1 = f"{cod1:03d}"
        str_cod2 = f"{cod2:03d}"

        m_str = f"{str_cod1}{str_cod2}"
        m_val = int(m_str)

        # Exponenciación modular propia
        c_val = exponenciacion_modular(m_val, e, n)
        c_str = f"{c_val:06d}"

        bloques_cifrados.append(c_str)
        bloques_detalle.append({
            "indice_bloque": (i // 2) + 1,
            "pareja_caracteres": [c1, c2],
            "pareja_visible": f"'{c1}' y '{c2}'",
            "codigos_ascii": [cod1, cod2],
            "bloque_texto_6d": m_str,
            "m_numerico": m_val,
            "c_numerico": c_val,
            "c_formateado_6d": c_str,
        })

    mensaje_cifrado = " ".join(bloques_cifrados)

    return {
        "mensaje_original": mensaje,
        "L": L,
        "hubo_relleno": hubo_relleno,
        "mensaje_con_relleno": mensaje_procesado,
        "p": p,
        "q": q,
        "e": e,
        "n": n,
        "phi": phi,
        "d": d,
        "llave_publica": (e, n),
        "llave_privada": (d, n),
        "bloques_cifrados": bloques_cifrados,
        "mensaje_cifrado_C": mensaje_cifrado,
        "detalle_pasos": bloques_detalle,
    }


# ==============================================================================
# 4. PROCESO DE DESENCRIPTACIÓN
# ==============================================================================

def desencriptar_mensaje(cifrado_c: str, L: int, p: int, q: int, e: int) -> Dict[str, Any]:
    """
    Ejecuta el protocolo completo de desencriptación RSA según las especificaciones:
    1. Valida p, q, e y calcula n, phi, d.
    2. Valida formato de C (bloques de 6 dígitos separados por espacios).
    3. Valida la coherencia de L con la cantidad de bloques k (L == 2k o L == 2k - 1).
    4. Descifra cada bloque: m = c^d (mod n).
    5. Separa m en dos códigos de 3 dígitos, valida rango [32, 126] y convierte a caracteres.
    6. Si L es impar, verifica que el último carácter sea un espacio y retira exactamente ese carácter.
    
    Retorna un diccionario con los resultados y el detalle de cada paso.
    """
    if not isinstance(L, int) or L <= 0:
        raise ValueError("La longitud L debe ser un entero positivo.")

    n, phi, d = validar_parametros_rsa(p, q, e)

    # Separar estrictamente por espacios (no tabulaciones ni saltos de línea)
    if "\t" in cifrado_c or "\n" in cifrado_c or "\r" in cifrado_c:
        raise ValueError("El mensaje cifrado C debe separar los bloques únicamente con espacios.")
    tokens = [t for t in cifrado_c.strip(" ").split(" ") if t]
    if not tokens:
        raise ValueError("El mensaje cifrado C no puede estar vacío.")

    k = len(tokens)
    # Coherencia de L con la cantidad de bloques
    if L not in (2 * k, 2 * k - 1):
        raise ValueError(
            f"Incoherencia en longitud L = {L} con la cantidad de bloques ({k} bloques). "
            f"Para {k} bloques, L debe ser {2 * k} (par) o {2 * k - 1} (impar con relleno)."
        )

    bloques_detalle = []
    texto_reconstruido_crudo = []

    for idx, token in enumerate(tokens):
        if len(token) != 6 or not all("0" <= ch <= "9" for ch in token):
            raise ValueError(
                f"El bloque {idx + 1} ('{token}') es inválido. "
                f"Cada bloque cifrado debe contener exactamente 6 dígitos decimales del 0 al 9."
            )

        c_val = int(token)
        if c_val < 0 or c_val >= n:
            raise ValueError(
                f"El bloque cifrado c = {c_val} está fuera de rango. Debe cumplir 0 <= c < n ({n})."
            )

        # Descifrado modular propio: m = c^d (mod n)
        m_val = exponenciacion_modular(c_val, d, n)
        m_str = f"{m_val:06d}"

        cod1 = int(m_str[:3])
        cod2 = int(m_str[3:])

        if cod1 < 32 or cod1 > 126:
            raise ValueError(
                f"Código ASCII recuperado {cod1} en bloque {idx + 1} fuera de rango admitido [32, 126]."
            )
        if cod2 < 32 or cod2 > 126:
            raise ValueError(
                f"Código ASCII recuperado {cod2} en bloque {idx + 1} fuera de rango admitido [32, 126]."
            )

        char1 = chr(cod1)
        char2 = chr(cod2)

        texto_reconstruido_crudo.extend([char1, char2])

        bloques_detalle.append({
            "indice_bloque": idx + 1,
            "c_str": token,
            "c_val": c_val,
            "m_val": m_val,
            "m_str_6d": m_str,
            "codigos_ascii": [cod1, cod2],
            "caracteres": [char1, char2],
            "texto_pareja": f"'{char1}' y '{char2}'",
        })

    texto_completo = "".join(texto_reconstruido_crudo)
    hubo_relleno = (L % 2 != 0)

    if hubo_relleno:
        # Se debe comprobar que el último carácter sea un espacio y retirar exactamente ese
        ultimo_caracter = texto_completo[-1]
        if ultimo_caracter != " ":
            raise ValueError(
                f"Error en validación de relleno: L = {L} es impar, pero el último carácter "
                f"recuperado no es un espacio (ASCII 32), sino '{ultimo_caracter}' (ASCII {ord(ultimo_caracter)})."
            )
        mensaje_final = texto_completo[:-1]
    else:
        mensaje_final = texto_completo

    return {
        "cifrado_original": cifrado_c,
        "L": L,
        "k_bloques": k,
        "hubo_relleno": hubo_relleno,
        "p": p,
        "q": q,
        "e": e,
        "n": n,
        "phi": phi,
        "d": d,
        "texto_crudo_con_relleno": texto_completo,
        "mensaje_recuperado": mensaje_final,
        "detalle_pasos": bloques_detalle,
    }


# ==============================================================================
# 5. ASISTENTE MATEMÁTICO: GENERACIÓN DE PRIMOS Y DESGLOSE PASO A PASO
# ==============================================================================

import random

def obtener_primos_en_rango(rango_min: int = 359, rango_max: int = 997) -> List[int]:
    """
    Retorna la lista de números primos dentro de un rango especificado.
    Por defecto abarca el rango óptimo [359, 997] donde cualquier pareja
    de primos p y q produce un módulo n en el rango válido 126126 < n < 1000000.
    """
    primos = []
    inicio = max(2, rango_min)
    for num in range(inicio, rango_max + 1):
        if es_primo(num):
            primos.append(num)
    return primos


def obtener_exponentes_compatibles(phi: int, limite: int = 15) -> List[int]:
    """
    Encuentra una lista amplia de exponentes públicos e recomendados y compatibles que satisfagan:
    e > 1 y MCD(e, phi) == 1.
    
    Evalúa un catálogo extenso de primos comunes en criptografía (desde primos pequeños
    como 3, 5, 7, 11 hasta números de Fermat como 257 y 65537).
    """
    candidatos = [
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 257, 65537
    ]
    compatibles = []
    
    for cand in candidatos:
        if cand < phi and mcd_euclides(cand, phi) == 1:
            compatibles.append(cand)
            if len(compatibles) >= limite:
                break
                
    return compatibles


def listar_todas_parejas_validas(filtro: str = "aleatorio") -> List[Tuple[int, int, int]]:
    """
    Genera dinámicamente el conjunto de todas las parejas únicas posibles de números primos (p, q)
    que satisfacen estrictamente la condición 126126 < n < 1000000.
    Existen más de 4,600 combinaciones posibles.
    """
    primos = obtener_primos_en_rango(359, 997)
    parejas = []
    
    for i in range(len(primos)):
        for j in range(i + 1, len(primos)):
            p, q = primos[i], primos[j]
            n = p * q
            if 126126 < n < 1000000:
                diff = abs(p - q)
                
                if filtro == "cercanos" and diff <= 30:
                    parejas.append((p, q, n))
                elif filtro == "asimetricos" and ((p < 500 and q > 700) or (q < 500 and p > 700)):
                    parejas.append((p, q, n))
                elif filtro == "pequeno" and n <= 300000:
                    parejas.append((p, q, n))
                elif filtro == "mediano" and (300000 < n <= 650000):
                    parejas.append((p, q, n))
                elif filtro == "grande" and n > 650000:
                    parejas.append((p, q, n))
                elif filtro in ("aleatorio", "todos"):
                    parejas.append((p, q, n))
                    
    return parejas


def sugerir_parametros_rsa(categoria: Any = "todos", indice_variante: int = 0) -> Dict[str, Any]:
    """
    Genera y sugiere una combinación válida y óptima de parámetros RSA (p, q, e).
    Permite tanto selección secuencial como generación dinámica a partir de las más de 4,600
    parejas de primos matemáticamente válidas. Acepta categoría como string o índice entero.
    """
    if isinstance(categoria, int):
        indice_variante = categoria
        categoria = "todos"
    elif not isinstance(categoria, str):
        categoria = str(categoria)
    # Mapear nombres de categoría amigables
    filtro_map = {
        "todos": "aleatorio",
        "aleatorio": "aleatorio",
        "pequeno": "pequeno",
        "mediano": "mediano",
        "grande": "grande",
        "cercanos": "cercanos",
        "asimetricos": "asimetricos"
    }
    f = filtro_map.get(categoria.lower(), "aleatorio")
    parejas = listar_todas_parejas_validas(f)
    
    if not parejas:
        parejas = listar_todas_parejas_validas("aleatorio")
        
    # Si se pide variante específica secuencial o caso inicial
    if indice_variante == 0 and categoria in ("todos", "pequeno"):
        p, q, n = 367, 373, 136891
        descripcion = "Caso de Referencia del Enunciado (p=367, q=373, n=136891)"
    else:
        # Selección usando el índice como semilla o posición
        idx = (indice_variante * 73 + 17) % len(parejas)
        p, q, n = parejas[idx]
        descripcion = f"Pareja generada dinámicamente ({categoria.capitalize()} · Opción {idx + 1} de {len(parejas)})"
        
    phi = (p - 1) * (q - 1)
    exponentes = obtener_exponentes_compatibles(phi, limite=12)
    e_rec = 17 if 17 in exponentes else (exponentes[0] if exponentes else 3)
    d = inverso_modular(e_rec, phi)
    
    return {
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
        "e_recomendado": e_rec,
        "d_calculado": d,
        "otros_e_compatibles": exponentes,
        "categoria": categoria,
        "descripcion": descripcion,
        "total_opciones_disponibles": len(parejas),
    }


def generar_pareja_aleatoria_libre(categoria: str = "todos") -> Dict[str, Any]:
    """
    Genera de forma completamente aleatoria e impredecible una pareja de primos
    con su exponente e recomendado dentro de las miles de combinaciones válidas.
    """
    parejas = listar_todas_parejas_validas(categoria)
    if not parejas:
        parejas = listar_todas_parejas_validas("aleatorio")
        
    p, q, n = random.choice(parejas)
    phi = (p - 1) * (q - 1)
    exponentes = obtener_exponentes_compatibles(phi, limite=12)
    e_rec = 17 if 17 in exponentes else (exponentes[0] if exponentes else 3)
    d = inverso_modular(e_rec, phi)
    
    return {
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
        "e_recomendado": e_rec,
        "d_calculado": d,
        "otros_e_compatibles": exponentes,
        "categoria": categoria,
        "descripcion": f"Pareja aleatoria única ({p}, {q}) entre {len(parejas):,} opciones válidas",
        "total_opciones_disponibles": len(parejas),
    }


def desglosar_calculos_paso_a_paso(p: int, q: int, e: int) -> Dict[str, Any]:
    """
    Genera el desglose matemático exhaustivo y didáctico de todos los cálculos:
    1. Primalidad de p y q.
    2. Cálculo de n y verificación del intervalo (126126, 1000000).
    3. Cálculo del Totiente de Euler phi = (p-1)(q-1).
    4. Traza de divisiones sucesivas del Algoritmo de Euclides para MCD(e, phi).
    5. Traza matricial de Bézout para encontrar coeficientes s y t.
    6. Reducción modular para exponente privado d (1 <= d < phi).
    7. Verificación de la identidad (e * d) mod phi = 1.
    """
    p_primo = es_primo(p)
    q_primo = es_primo(q)
    distintos = (p != q)
    
    n = p * q
    n_en_rango = (126126 < n < 1000000)
    phi = (p - 1) * (q - 1) if (p > 1 and q > 1) else 0
    
    # 1. Traza de divisiones del Algoritmo de Euclides
    pasos_euclides = []
    r0, r1 = abs(e), abs(phi)
    while r1 != 0:
        cociente = r0 // r1
        residuo = r0 % r1
        pasos_euclides.append({
            "dividendo": r0,
            "divisor": r1,
            "cociente": cociente,
            "residuo": residuo,
            "ecuacion": f"{r0} = {r1} × ({cociente}) + {residuo}"
        })
        r0, r1 = r1, residuo
    mcd = r0
    es_coprimo = (mcd == 1 and e > 1)
    
    # 2. Traza matricial de Bézout
    pasos_bezout = []
    m = [[1, 0], [0, 1]]
    r0, r1 = e, phi
    paso_k = 0
    
    while r1 != 0:
        q_k = r0 // r1
        rem_k = r0 % r1
        m_sig = [m[1], [m[0][0] - q_k * m[1][0], m[0][1] - q_k * m[1][1]]]
        pasos_bezout.append({
            "paso": paso_k + 1,
            "dividendo": r0,
            "divisor": r1,
            "cociente": q_k,
            "residuo": rem_k,
            "matriz_antes": f"[[{m[0][0]}, {m[0][1]}], [{m[1][0]}, {m[1][1]}]]",
            "matriz_despues": f"[[{m_sig[0][0]}, {m_sig[0][1]}], [{m_sig[1][0]}, {m_sig[1][1]}]]",
            "coef_s": m_sig[0][0],
            "coef_t": m_sig[0][1],
        })
        m = m_sig
        r0, r1 = r1, rem_k
        paso_k += 1
        
    s_final = m[0][0]
    t_final = m[0][1]
    
    d_val = None
    verificacion_ok = False
    if es_coprimo and phi > 1:
        d_val = s_final % phi
        if d_val < 1:
            d_val += phi
        verificacion_ok = ((e * d_val) % phi == 1)
        
    return {
        "p": p,
        "q": q,
        "e": e,
        "p_es_primo": p_primo,
        "q_es_primo": q_primo,
        "primos_distintos": distintos,
        "n": n,
        "n_en_rango": n_en_rango,
        "phi": phi,
        "mcd": mcd,
        "es_coprimo": es_coprimo,
        "pasos_euclides": pasos_euclides,
        "pasos_bezout": pasos_bezout,
        "coeficiente_s": s_final,
        "coeficiente_t": t_final,
        "ecuacion_bezout": f"{e} × ({s_final}) + {phi} × ({t_final}) = {mcd}",
        "d_calculado": d_val,
        "verificacion_modular": f"({e} × {d_val}) mod {phi} = {(e * d_val) % phi if d_val else 'N/A'}",
        "verificacion_ok": verificacion_ok,
    }
