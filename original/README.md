# Proyecto de Criptografía RSA
**Curso:** MM2015 Matemática Discreta 1 · Semestre 4  
**Evaluación:** Proyecto 3 (Parcial 3)  
**Grupo:** Grupo No. 13  
**Integrantes del Equipo:**
- Pablo Javier Orantes Suchini (#25563)
- Barbara Fabiola Garzaro Mendez (#25504)

**Versión de Python recomendada:** Python 3.10+ (compatible con Python 3.10, 3.11, 3.12 y 3.13)

---

## 1. Instrucciones Rápidas de Ejecución

El proyecto está desarrollado **100% en Python puro** (sin HTML, sin CSS y sin servidores web), utilizando una interfaz gráfica moderna de escritorio construida con **CustomTkinter**:

1. **Abrir la terminal dentro de la carpeta del proyecto** (donde se encuentran `main.py` y `requirements.txt`):
   ```bash
   cd "ruta/a/Proyecto 3"
   ```
   *(Si ejecutas `pip` desde otra carpeta, mostrará el error `No such file or directory: 'requirements.txt'`.)*
2. **Instalar dependencias necesarias:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Iniciar la aplicación:**
   ```bash
   python main.py
   ```
   *(La ventana de la aplicación gráfica se abrirá de inmediato con el caso de prueba listo para interactuar).*

### Ejecución de Pruebas Automatizadas:
Para correr la suite completa de 16 pruebas unitarias:
```bash
python main.py --test
```

---

## 2. Estructura del Código y Portabilidad

Todos los módulos del proyecto se comunican mediante **rutas relativas** e importaciones limpias en Python, garantizando su correcta ejecución en cualquier computadora y sistema operativo (Windows, macOS, Linux):

```text
Grupo_No.13_Proyecto/
├── main.py              # Punto de entrada principal (ejecuta la GUI directamente)
├── gui.py               # Interfaz gráfica moderna 100% Python (CustomTkinter)
├── crypto_rsa.py        # Núcleo matemático de algoritmos propios sin librerías prohibidas
├── test_rsa.py          # Suite de 16 pruebas unitarias automatizadas
├── requirements.txt     # Dependencias (customtkinter)
└── README.md            # Documento de lectura rápida y especificaciones del proyecto
```

---

## 3. Identificación de Algoritmos Matemáticos Propios y Módulos de Ayuda

En estricto cumplimiento del enunciado, **no se utiliza `math.gcd`**, ni la versión modular de `pow(base, exp, mod)` con 3 argumentos, ni `pow(e, -1, phi)`, ni librerías externas de criptografía. Cada operación se programó de forma artesanal desde cero en [`crypto_rsa.py`](crypto_rsa.py).

A continuación se detalla cada algoritmo implementado, pensado para una lectura clara tanto en visores Markdown como en texto plano (Bloc de notas):

### 1. Comprobación de Primalidad
- **Función:** `es_primo(num: int) -> bool`
- **¿Qué hace y cómo funciona?:**  
  Determina si un número dado es primo descartando primero casos directos (números menores a 2, pares y múltiplos de 3). Para números mayores, aplica una búsqueda de divisores optimizada en pasos de 6k ± 1 hasta la raíz cuadrada del número ($\sqrt{n}$). Este método reduce drásticamente las operaciones necesarias y garantiza que los números p y q elegidos sean primos matemáticos legítimos.

### 2. Máximo Común Divisor (MCD)
- **Función:** `mcd_euclides(a: int, b: int) -> int`
- **¿Qué hace y cómo funciona?:**  
  Implementa el método tradicional de divisiones sucesivas propuesto por Euclides. Va calculando el residuo de la división entera entre ambos valores de forma iterativa (`a, b = b, a % b`) hasta que el residuo llega a cero. Se usa para verificar que el exponente público e sea coprimo con el totiente phi, es decir, que cumpla estrictamente con MCD(e, phi) = 1.

### 3. Inverso Multiplicativo Modular
- **Función:** `inverso_modular(e: int, phi: int) -> int` (apoyada en `bezout_matricial`)
- **¿Qué hace y cómo funciona?:**  
  Resuelve la congruencia lineal `e * d ≡ 1 (mod phi)` para calcular la clave privada d. En lugar de limitarse a una recursión simple, utiliza el método matricial de las identidades de Bézout sobre el Algoritmo Extendido de Euclides. Multiplica matrices de transformación 2x2 asociadas a cada cociente entero sucesivo, rastreando los coeficientes lineales de forma exacta y ajustando el resultado a un valor positivo dentro del rango `[1, phi - 1]`.

### 4. Exponenciación Modular Rápida
- **Función:** `exponenciacion_modular(base: int, exp: int, mod: int) -> int`
- **¿Qué hace y cómo funciona?:**  
  Calcula potencias gigantescas del tipo `(base ^ exp) mod mod` (necesarias tanto para encriptar como para desencriptar) sin desbordar la memoria ni colgar el procesador. Descompone el exponente en su representación binaria y avanza mediante la técnica de "elevar al cuadrado y multiplicar", aplicando el operador módulo (%) en cada paso intermedio.

### 5. Asistente Dinámico de Selección de Primos
- **Funciones:** `sugerir_parametros_rsa()`, `generar_pareja_aleatoria_libre()`, `listar_todas_parejas_validas()`, `obtener_exponentes_compatibles()`
- **¿Qué hace y cómo funciona?:**  
  Módulo de asistencia didáctica que precalcula y valida el catálogo completo de 4,656 parejas de primos disponibles en el intervalo [359, 997] que garantizan que el módulo n caiga exactamente en la ventana requerida (126,126 < n < 1,000,000). Permite generar combinaciones aleatorias infinitas, aplicar filtros de longitud/estructura y ofrecer botones interactivos para elegir únicamente exponentes e que sean coprimos válidos.

### 6. Desglose Matemático Paso a Paso
- **Función:** `desglosar_calculos_paso_a_paso(p, q, e)`
- **¿Qué hace y cómo funciona?:**  
  Función orientada a la auditoría y aprendizaje académico. Reconstruye y formatea como texto explicativo la tabla de divisiones sucesivas de Euclides (cocientes y residuos), la secuencia de matrices de Bézout generadas, la ecuación diofántica resultante y la comprobación final de que `(e * d) mod phi = 1`.

---

## 4. Módulos de la Interfaz Gráfica

La aplicación incluye 6 pestañas interactivas organizadas lógicamente:
1. **Encriptar Mensaje:** Encriptación de texto a bloques de 6 dígitos con contador de longitud $L$, verificación de relleno e informe por bloques.
2. **Desencriptar Mensaje:** Desencriptación modular $m \equiv c^d \pmod{n}$, recuperación exacta de espacios originales y retiro del espacio de relleno si $L$ es impar.
3. **Asistente de Primos:** Generador dinámico con más de 4,600 parejas válidas, botón aleatorio único para variedad ilimitada, filtros de tamaño/estructura, presets directos, selección manual asistida con ComboBoxes y botones/chips interactivos para elegir exponentes $e$ compatibles con recálculo inmediato de $d$.
4. **Desglose Matemático:** Módulo didáctico que expone la traza completa de cómo se hicieron los cálculos: divisiones sucesivas del MCD, evolución de las matrices de coeficientes de Bézout, ecuación lineal resultante y comprobación de congruencia modular.
5. **Instrucciones y Pasos a Seguir:** Guía detallada paso a paso para el usuario, explicación del flujo de trabajo, preguntas frecuentes y una lista de verificación específica para la grabación del video demostrativo.
6. **Auditoría de Código:** Visor del código fuente de los algoritmos propios para revisión directa del docente.

---

## 5. Uso de las Operaciones y Funcionamiento

### 5.1 Encriptación
1. **Entradas:**
   - Primos $p$ y $q$: deben ser primos distintos y cumplir $126126 < n < 1000000$.
   - Exponente público $e$: debe cumplir $e > 1$ y $\text{MCD}(e, \varphi) = 1$.
   - Mensaje $M$: caracteres ASCII imprimibles entre 32 y 126.
2. **Proceso y Relleno (Padding):**
   - Se registra la longitud original $L = \text{len}(M)$.
   - **Si $L$ es impar:** Se añade exactamente **un espacio** (`' '`, ASCII 032) al final del mensaje.
   - **Si $L$ es par:** No se añade ningún relleno.
   - El texto se divide en parejas de 2 caracteres, convirtiendo cada carácter a su código ASCII de 3 dígitos (ej. `'A'` $\to 065$) para formar un bloque numérico $m$ de 6 dígitos.
   - Cada bloque se cifra como $c \equiv m^e \pmod{n}$ y se representa con exactamente 6 dígitos (con ceros a la izquierda si es necesario).
3. **Salidas (dónde se muestran $C$ y $L$):**
   - En el panel de resultados de la pestaña **Encriptar Mensaje** se muestran directamente:
     - El **Mensaje Cifrado $C$** (bloques de 6 dígitos separados por espacios, con botón para copiar).
     - La **Longitud original $L$** (junto con la indicación de si se aplicó relleno).
     - La **Llave pública $(e, n)$**, el totiente $\varphi(n)$ y la tabla de conversión ASCII / bloques.

### 5.2 Desencriptación
1. **Entradas (cómo ingresar $C$ y $L$):**
   - En la pestaña **Desencriptar Mensaje**, pegue o escriba los bloques de 6 dígitos separados por espacios en el campo **Mensaje Cifrado $C$**, ingrese el número entero en el campo **Longitud Original $L$**, e introduzca los primos $p, q$ y el exponente $e$ (también puede usar el botón de carga rápida desde la encriptación).
2. **Proceso y Recuperación:**
   - Se calcula $n = p \cdot q$, $\varphi = (p - 1)(q - 1)$ y $d$ (inverso modular de $e \pmod{\varphi}$).
   - Se comprueba la coherencia de $L$ con el número de bloques $k$ ($L$ debe ser $2k$ o $2k - 1$).
   - Para cada bloque cifrado $c$, se recupera $m \equiv c^d \pmod{n}$, se formatea a 6 dígitos y se divide en dos códigos ASCII.
   - **Retiro de Relleno:** Si $L$ es impar, el sistema valida que el último carácter recuperado sea un espacio (`' '`) y retira **únicamente** ese carácter. Si $L$ es par, se mantiene completo.
   - **Preservación:** No se utiliza eliminación general de espacios (`.strip()`), garantizando que los espacios originales al inicio, en medio y al final se conserven intactos.

---

## 6. Ejemplo de Referencia del Enunciado

Al presionar el botón **"Cargar Caso de RSA"** en la interfaz se cargan los valores exactos de la página 4 del PDF:

* **Mensaje original:** `"RSA"`
* **Entradas:** $p = 367$, $q = 373$, $e = 17$
* **Valores Calculados:**
  * Módulo $n = 367 \times 373 = 136891$ (cumple $126126 < 136891 < 1000000$).
  * Totiente $\varphi(n) = 366 \times 372 = 136152$.
  * $\text{MCD}(17, 136152) = 1$.
  * Exponente privado $d = 8009$.
* **Tratamiento del Mensaje y Relleno:**
  * Longitud original $L = 3$ (impar).
  * Mensaje con relleno: `"RSA "`
  * Pareja 1: `'R'` (082) y `'S'` (083) $\to m_1 = 082083 \implies c_1 \equiv 82083^{17} \pmod{136891} = \mathbf{026054}$
  * Pareja 2: `'A'` (065) y `' '` (032) $\to m_2 = 065032 \implies c_2 \equiv 65032^{17} \pmod{136891} = \mathbf{123875}$
* **Cifrado resultante $C$:** `026054 123875`
* **Desencriptación:**
  * $m_1 \equiv 26054^{8009} \pmod{136891} = 082083 \to \text{"RS"}$
  * $m_2 \equiv 123875^{8009} \pmod{136891} = 065032 \to \text{"A "}$
  * Texto con relleno: `"RSA "` $\to$ al ser $L=3$, se retira el espacio final $\to \mathbf{"RSA"}$.

---

## 7. Comprobaciones Realizadas

La suite automatizada en [`test_rsa.py`](test_rsa.py) valida:
1. Recuperación exacta con longitudes pares e impares.
2. Uso de mayúsculas, minúsculas, números, espacios consecutivos y signos.
3. Ceros iniciales en los bloques cifrados formateados a 6 dígitos.
4. Rechazo de parámetros RSA inválidos (no primos, $n$ fuera de rango, $e$ no coprimo, eñes/tildes, longitudes inconsistentes, bloques mal formados y valores cifrados fuera de rango $c \ge n$).
5. Funcionamiento correcto del asistente de sugerencia de primos y exponentes compatibles.
6. Exactitud de las trazas de divisiones de Euclides y matrices de Bézout.

---

## 8. Referencias y Bibliografía

1. **Rosen, K. H.** (2019). *Discrete Mathematics and Its Applications* (8va ed.). McGraw-Hill Education.  
   *(Referencia fundamental para Teoría de Números: Algoritmo de Euclides, Identidad de Bézout, Aritmética Modular y el Criptosistema RSA).*
2. **Rivest, R. L., Shamir, A., & Adleman, L.** (1978). *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems*. Communications of the ACM, 21(2), 120–126.  
   *(Artículo seminal donde se presenta formalmente el algoritmo criptográfico RSA).*
3. **Cormen, T. H., Leiserson, C. E., Rivest, R. L., & Stein, C.** (2009). *Introduction to Algorithms* (3ra ed.). The MIT Press.  
   *(Capítulo 31: Algoritmos de Teoría de Números, exponenciación binaria modular y cálculo del inverso multiplicativo modular).*
4. **Google DeepMind.** (2024). *Gemini: A Family of Highly Capable Multimodal Models*. Google. https://deepmind.google/technologies/gemini/  
   *(Modelo de inteligencia artificial utilizado como soporte en la asistencia de codificación, documentación técnica y estructuración del proyecto).*
5. **Python Software Foundation.** (2024). *The Python Standard Library Documentation*. https://docs.python.org/3/  
   *(Especificación del lenguaje y manejo de aritmética de enteros con precisión arbitraria).*
6. **Tom Schimansky.** (2024). *CustomTkinter: A modern and customizable python UI-library based on Tkinter*. https://github.com/TomSchimansky/CustomTkinter  
   *(Librería gráfica utilizada para la construcción de la interfaz visual moderna de escritorio).*

---

## 9. Declaración de Asistencia de Inteligencia Artificial

En concordancia con las buenas prácticas de integridad académica y transparencia tecnológica:

- **Asistente y Modelo Utilizado:** **Google Gemini** (Gemini 3.8 Flash a través del entorno Antigravity de Google DeepMind).
- **Alcance y Propósito de la Asistencia:**
  - Revisión de la suite de pruebas unitarias automatizadas (`test_rsa.py`).
  - Apoyo en el diseño y distribución visual de los componentes de la interfaz de usuario en `CustomTkinter` (`gui.py`).
  - Verificación matemática de la congruencia modular y del método matricial de Bézout para la traza pedagógica en `crypto_rsa.py`.
  - Apoyo en redacción técnica y ordenamiento del archivo `README.md`.
- **Autoría Intelectual y Validación:** Todo el código, lógica algorítmica y criterios de diseño fueron revisados, validados, ejecutados y probados directamente por los integrantes del equipo (Grupo No. 13).
