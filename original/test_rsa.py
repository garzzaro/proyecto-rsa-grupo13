"""
Suite de Pruebas Unitarias y de Integración - Proyecto Criptografía RSA
MM2015 Matemática Discreta 1 · Grupo 13

Verifica exhaustivamente:
1. Caso de referencia del enunciado ("RSA", p=367, q=373, e=17).
2. Mensajes pares e impares, mayúsculas, minúsculas, números, signos.
3. Preservación estricta de espacios al inicio, centro y final.
4. Generación y manejo de ceros iniciales en bloques cifrados.
5. Rechazo y validación de errores matemáticos y de formato.
6. Asistente matemático: generador de primos, sugerencia de llaves y desglose paso a paso.
"""

import unittest
from crypto_rsa import (
    mcd_euclides,
    bezout_matricial,
    inverso_modular,
    exponenciacion_modular,
    es_primo,
    validar_parametros_rsa,
    validar_caracteres_ascii,
    encriptar_mensaje,
    desencriptar_mensaje,
    obtener_primos_en_rango,
    obtener_exponentes_compatibles,
    sugerir_parametros_rsa,
    generar_pareja_aleatoria_libre,
    listar_todas_parejas_validas,
    desglosar_calculos_paso_a_paso,
)


class TestCriptografiaRSA(unittest.TestCase):
    """Suite de pruebas unitarias para el módulo de criptografía RSA."""

    def test_caso_referencia_enunciado(self):
        """Verifica exactamente el caso de prueba especificado en la página 4 del PDF."""
        p = 367
        q = 373
        e = 17
        mensaje = "RSA"

        # 1. Encriptación
        res_enc = encriptar_mensaje(mensaje, p, q, e)
        self.assertEqual(res_enc["n"], 136891)
        self.assertEqual(res_enc["phi"], 136152)
        self.assertEqual(res_enc["d"], 8009)
        self.assertEqual(res_enc["L"], 3)
        self.assertTrue(res_enc["hubo_relleno"])
        self.assertEqual(res_enc["mensaje_con_relleno"], "RSA ")
        self.assertEqual(res_enc["bloques_cifrados"], ["026054", "123875"])
        self.assertEqual(res_enc["mensaje_cifrado_C"], "026054 123875")

        # 2. Desencriptación
        res_dec = desencriptar_mensaje(
            cifrado_c=res_enc["mensaje_cifrado_C"],
            L=res_enc["L"],
            p=p,
            q=q,
            e=e,
        )
        self.assertEqual(res_dec["d"], 8009)
        self.assertEqual(res_dec["mensaje_recuperado"], "RSA")

    def test_mensaje_longitud_par_sin_relleno(self):
        """Verifica que mensajes con longitud par no agreguen ni retiren relleno."""
        p = 367
        q = 373
        e = 17
        mensaje = "HOLA"  # L = 4 (par)

        res_enc = encriptar_mensaje(mensaje, p, q, e)
        self.assertFalse(res_enc["hubo_relleno"])
        self.assertEqual(res_enc["L"], 4)

        res_dec = desencriptar_mensaje(res_enc["mensaje_cifrado_C"], res_enc["L"], p, q, e)
        self.assertEqual(res_dec["mensaje_recuperado"], mensaje)

    def test_preservacion_estricta_de_espacios(self):
        """Verifica que espacios al inicio, en medio y al final se conserven intactos."""
        p = 401
        q = 409  # n = 164009
        e = 23
        mensaje = "  Hola  Mundo!  "  # Espacios múltiples

        res_enc = encriptar_mensaje(mensaje, p, q, e)
        res_dec = desencriptar_mensaje(res_enc["mensaje_cifrado_C"], res_enc["L"], p, q, e)
        self.assertEqual(res_dec["mensaje_recuperado"], mensaje)

    def test_caracteres_especiales_y_signos(self):
        """Prueba con números, símbolos y signos ASCII permitidos [32, 126]."""
        p = 503
        q = 509  # n = 256027
        e = 19
        mensaje = "Cripto-2026: (x + y) * [z] = 100% #OK!"

        res_enc = encriptar_mensaje(mensaje, p, q, e)
        res_dec = desencriptar_mensaje(res_enc["mensaje_cifrado_C"], res_enc["L"], p, q, e)
        self.assertEqual(res_dec["mensaje_recuperado"], mensaje)

    def test_ceros_iniciales_en_cifrado(self):
        """Verifica que los bloques cifrados menores a 100000 mantengan ceros iniciales."""
        p = 367
        q = 373
        e = 17
        res = encriptar_mensaje("RSA", p, q, e)
        self.assertTrue(res["bloques_cifrados"][0].startswith("0"))
        self.assertEqual(len(res["bloques_cifrados"][0]), 6)

    def test_rechazo_primos_invalidos(self):
        """Debe rechazar si p o q no son primos o si son iguales."""
        with self.assertRaises(ValueError):
            validar_parametros_rsa(368, 373, 17)
        with self.assertRaises(ValueError):
            validar_parametros_rsa(367, 367, 17)

    def test_rechazo_modulo_fuera_de_rango(self):
        """n debe estar estrictamente en 126126 < n < 1000000."""
        with self.assertRaises(ValueError):
            validar_parametros_rsa(101, 103, 17)
        with self.assertRaises(ValueError):
            validar_parametros_rsa(1009, 1013, 17)

    def test_rechazo_e_no_coprimo(self):
        """e debe ser coprimo con phi."""
        p, q = 367, 373  # phi = 136152
        with self.assertRaises(ValueError):
            validar_parametros_rsa(p, q, 18)

    def test_rechazo_caracteres_no_admitidos(self):
        """Debe rechazar tildes, eñes y caracteres fuera de [32, 126]."""
        with self.assertRaises(ValueError):
            validar_caracteres_ascii("Hola año 2026")
        with self.assertRaises(ValueError):
            validar_caracteres_ascii("Canción")
        with self.assertRaises(ValueError):
            validar_caracteres_ascii("Salto\nde línea")

    def test_rechazo_longitud_incoherente_en_desencriptacion(self):
        """Si hay k bloques, L debe ser 2k o 2k - 1."""
        p, q, e = 367, 373, 17
        cifrado = "026054 123875"  # 2 bloques -> L debe ser 3 o 4
        with self.assertRaises(ValueError):
            desencriptar_mensaje(cifrado, 5, p, q, e)
        with self.assertRaises(ValueError):
            desencriptar_mensaje(cifrado, 2, p, q, e)

    def test_rechazo_bloques_mal_formados(self):
        """Cada bloque debe tener exactamente 6 dígitos decimales (0-9) separados por espacios."""
        p, q, e = 367, 373, 17
        with self.assertRaises(ValueError):
            desencriptar_mensaje("26054 123875", 3, p, q, e)  # 5 dígitos
        with self.assertRaises(ValueError):
            desencriptar_mensaje("02605A 123875", 3, p, q, e)  # letras
        with self.assertRaises(ValueError):
            desencriptar_mensaje("026054\t123875", 3, p, q, e)  # tabulación

    def test_rechazo_valores_cifrados_fuera_de_rango(self):
        """Cada bloque cifrado c debe cumplir 0 <= c < n."""
        p, q, e = 367, 373, 17  # n = 136891
        with self.assertRaises(ValueError):
            desencriptar_mensaje("136891 123875", 3, p, q, e)  # c == n
        with self.assertRaises(ValueError):
            desencriptar_mensaje("999999 123875", 3, p, q, e)  # c > n

    def test_asistente_sugerencia_primos_y_exponentes(self):
        """Verifica que el generador y sugeridor produzca siempre parámetros válidos."""
        for i in range(5):
            sug = sugerir_parametros_rsa(i)
            self.assertTrue(es_primo(sug["p"]))
            self.assertTrue(es_primo(sug["q"]))
            self.assertNotEqual(sug["p"], sug["q"])
            self.assertTrue(126126 < sug["n"] < 1000000)
            self.assertEqual(mcd_euclides(sug["e_recomendado"], sug["phi"]), 1)
            self.assertEqual((sug["e_recomendado"] * sug["d_calculado"]) % sug["phi"], 1)
            self.assertTrue(len(sug["otros_e_compatibles"]) > 0)

    def test_desglose_matematico_completo(self):
        """Comprueba que la traza paso a paso contenga las divisiones y ecuaciones de Bézout."""
        info = desglosar_calculos_paso_a_paso(367, 373, 17)
        self.assertTrue(info["p_es_primo"])
        self.assertTrue(info["q_es_primo"])
        self.assertTrue(info["es_coprimo"])
        self.assertTrue(info["verificacion_ok"])
        self.assertEqual(info["d_calculado"], 8009)
        self.assertTrue(len(info["pasos_euclides"]) > 0)
        self.assertTrue(len(info["pasos_bezout"]) > 0)

    def test_catalogo_4656_parejas_validas(self):
        """Verifica que el catálogo calcule exactamente más de 4,600 combinaciones válidas."""
        parejas_todas = listar_todas_parejas_validas("todos")
        self.assertEqual(len(parejas_todas), 4656)
        
        # Validar filtros específicos
        cercanos = listar_todas_parejas_validas("cercanos")
        self.assertTrue(len(cercanos) > 0)
        for p, q, n in cercanos[:10]:
            self.assertTrue(abs(p - q) <= 30)
            self.assertTrue(126126 < n < 1000000)

    def test_generador_aleatorio_libre_y_variedad(self):
        """Verifica que el generador aleatorio libre produzca combinaciones variadas y válidas."""
        combinaciones = set()
        for _ in range(15):
            res = generar_pareja_aleatoria_libre("aleatorio")
            self.assertTrue(es_primo(res["p"]))
            self.assertTrue(es_primo(res["q"]))
            self.assertTrue(126126 < res["n"] < 1000000)
            self.assertEqual(mcd_euclides(res["e_recomendado"], res["phi"]), 1)
            combinaciones.add((res["p"], res["q"]))

        # Al menos deben haberse generado combinaciones distintas
        self.assertGreater(len(combinaciones), 1)


if __name__ == "__main__":
    unittest.main()
