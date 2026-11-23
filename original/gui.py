"""
Interfaz Gráfica Moderna en Python Puro (CustomTkinter)
Proyecto Criptografía RSA - MM2015 Matemática Discreta 1 · Grupo 13

Desarrollada 100% en Python, sin HTML/CSS ni servidores externos.
Aplica principios de diseño profesional y humano:
- Tema visual moderno y limpio (Dark / Light mode).
- Asistente inteligente de generación y sugerencia de primos con opciones y filtros.
- Módulo didáctico de instrucciones y pasos a seguir (guía de uso y checklist para video).
- Módulo de desglose matemático detallado paso a paso (Euclides y Bézout matricial).
- Tablas de bloques interactivas para encriptación y desencriptación.
- Validaciones comprensibles en tiempo real sin cierres inesperados.
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox
from typing import Dict, Any, List

# Manejo de importación segura de CustomTkinter con fallback a tkinter estándar
try:
    import customtkinter as ctk
    USAR_CUSTOM_TK = True
except ImportError:
    import tkinter.ttk as ttk
    USAR_CUSTOM_TK = False

from crypto_rsa import (
    es_primo,
    mcd_euclides,
    inverso_modular,
    validar_parametros_rsa,
    encriptar_mensaje,
    desencriptar_mensaje,
    obtener_primos_en_rango,
    obtener_exponentes_compatibles,
    sugerir_parametros_rsa,
    generar_pareja_aleatoria_libre,
    listar_todas_parejas_validas,
    desglosar_calculos_paso_a_paso,
)


class AppCriptografiaRSA(ctk.CTk if USAR_CUSTOM_TK else tk.Tk):
    """Ventana principal de la aplicación gráfica para criptografía RSA."""
    def __init__(self):
        """Inicializa la ventana principal, el tema visual y los componentes de la interfaz."""
        super().__init__()

        self.title("Criptografía RSA · MM2015 Matemática Discreta 1 · Grupo 13")
        self.geometry("1140x820")
        self.minsize(980, 720)

        if USAR_CUSTOM_TK:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")

        self.indice_sugerencia_actual = 0
        self.categoria_filtro_actual = "todos"
        self.sug_actual = sugerir_parametros_rsa("todos", 0)
        self._crear_componentes()

    def _crear_componentes(self):
        """Construye la barra superior, el contenedor de pestañas y carga el caso de referencia."""
        # ======================================================================
        # 1. HEADER SUPERIOR
        # ======================================================================
        header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=("#e2e8f0", "#1e293b"))
        header_frame.pack(fill="x", side="top", padx=0, pady=0)

        header_content = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_content.pack(fill="x", padx=20, pady=12)

        # Brand / Título
        title_box = ctk.CTkFrame(header_content, fg_color="transparent")
        title_box.pack(side="left")

        lbl_badge = ctk.CTkLabel(
            title_box,
            text="MM2015 · Grupo 13",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#2563eb",
            text_color="#ffffff",
            corner_radius=6,
            padx=8,
            pady=2
        )
        lbl_badge.pack(side="left", padx=(0, 12))

        lbl_title = ctk.CTkLabel(
            title_box,
            text="Criptografía RSA",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=("#0f172a", "#f8fafc")
        )
        lbl_title.pack(side="left")

        lbl_sub = ctk.CTkLabel(
            title_box,
            text="  |  Matemática Discreta 1  ·  Algoritmos Propios",
            font=ctk.CTkFont(size=13),
            text_color=("#64748b", "#94a3b8")
        )
        lbl_sub.pack(side="left")

        # Acciones superiores
        actions_box = ctk.CTkFrame(header_content, fg_color="transparent")
        actions_box.pack(side="right")

        # Texto del botón actualizado: "Cargar Caso de RSA"
        btn_sample = ctk.CTkButton(
            actions_box,
            text="Cargar Caso de RSA",
            command=self.cargar_caso_referencia,
            fg_color="#059669",
            hover_color="#047857",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=32
        )
        btn_sample.pack(side="left", padx=8)

        self.theme_switch = ctk.CTkSwitch(
            actions_box,
            text="Modo Oscuro",
            command=self.toggle_theme,
            onvalue="dark",
            offvalue="light"
        )
        self.theme_switch.select()
        self.theme_switch.pack(side="left", padx=8)

        # ======================================================================
        # 2. CONTENEDOR DE PESTAÑAS (TABS)
        # ======================================================================
        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(10, 16))

        self.tab_enc = self.tabview.add("  Encriptar Mensaje  ")
        self.tab_dec = self.tabview.add("  Desencriptar Mensaje  ")
        self.tab_helper = self.tabview.add("  Asistente de Primos  ")
        self.tab_trace = self.tabview.add("  Desglose Matemático  ")
        self.tab_guide = self.tabview.add("  Instrucciones y Pasos  ")
        self.tab_audit = self.tabview.add("  Auditoría de Código  ")

        self._construir_tab_encriptar()
        self._construir_tab_desencriptar()
        self._construir_tab_asistente()
        self._construir_tab_desglose()
        self._construir_tab_instrucciones()
        self._construir_tab_auditoria()

        # Cargar valores iniciales del ejemplo
        self.cargar_caso_referencia(ejecutar_inicial=True)

    # ==========================================================================
    # PESTAÑA 1: ENCRIPTAR
    # ==========================================================================
    def _construir_tab_encriptar(self):
        """Construye la pestaña de encriptación con entradas de parámetros, mensaje y resultados."""
        top_grid = ctk.CTkFrame(self.tab_enc, fg_color="transparent")
        top_grid.pack(fill="x", padx=10, pady=10)
        top_grid.grid_columnconfigure(0, weight=3)
        top_grid.grid_columnconfigure(1, weight=2)

        # Panel izquierdo: Entradas
        in_card = ctk.CTkFrame(top_grid, corner_radius=8)
        in_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)

        lbl_in_title = ctk.CTkLabel(
            in_card,
            text="Parámetros de Encriptación",
            font=ctk.CTkFont(size=15, weight="bold")
        )
        lbl_in_title.pack(anchor="w", padx=16, pady=(12, 8))

        # Fila de números primos p, q y e
        p_row = ctk.CTkFrame(in_card, fg_color="transparent")
        p_row.pack(fill="x", padx=16, pady=4)

        ctk.CTkLabel(p_row, text="Primo p:", font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self.enc_p_entry = ctk.CTkEntry(p_row, width=90, font=ctk.CTkFont(family="Consolas", size=13))
        self.enc_p_entry.grid(row=0, column=1, padx=(0, 14))

        ctk.CTkLabel(p_row, text="Primo q:", font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=2, sticky="w", padx=(0, 4))
        self.enc_q_entry = ctk.CTkEntry(p_row, width=90, font=ctk.CTkFont(family="Consolas", size=13))
        self.enc_q_entry.grid(row=0, column=3, padx=(0, 14))

        ctk.CTkLabel(p_row, text="Exponente e:", font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=4, sticky="w", padx=(0, 4))
        self.enc_e_entry = ctk.CTkEntry(p_row, width=90, font=ctk.CTkFont(family="Consolas", size=13))
        self.enc_e_entry.grid(row=0, column=5, padx=(0, 0))

        # Mensaje a encriptar
        ctk.CTkLabel(in_card, text="Mensaje original (M):", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=16, pady=(8, 2))
        self.enc_txt = ctk.CTkTextbox(in_card, height=65, font=ctk.CTkFont(size=13))
        self.enc_txt.pack(fill="x", padx=16, pady=(0, 4))
        self.enc_txt.bind("<KeyRelease>", self._actualizar_contador_caracteres)

        # Meta de caracteres y botones de acción
        action_row = ctk.CTkFrame(in_card, fg_color="transparent")
        action_row.pack(fill="x", padx=16, pady=(4, 12))

        self.enc_len_label = ctk.CTkLabel(action_row, text="Longitud: 3 caracteres · impar (+1 espacio)", text_color="#94a3b8", font=ctk.CTkFont(size=12))
        self.enc_len_label.pack(side="left")

        btn_enc = ctk.CTkButton(
            action_row,
            text="Encriptar Mensaje",
            command=self.accion_encriptar,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            font=ctk.CTkFont(weight="bold"),
            width=150
        )
        btn_enc.pack(side="right")

        # Panel derecho: Métricas de Llave y Módulo
        metrics_card = ctk.CTkFrame(top_grid, corner_radius=8)
        metrics_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=0)

        lbl_met_title = ctk.CTkLabel(
            metrics_card,
            text="Valores Modulares Calculados",
            font=ctk.CTkFont(size=15, weight="bold")
        )
        lbl_met_title.pack(anchor="w", padx=16, pady=(12, 8))

        self.enc_lbl_n = ctk.CTkLabel(metrics_card, text="Módulo n = p × q: 136891  (Válido)", anchor="w", font=ctk.CTkFont(size=13))
        self.enc_lbl_n.pack(fill="x", padx=16, pady=2)

        self.enc_lbl_phi = ctk.CTkLabel(metrics_card, text="Euler φ(n) = (p-1)(q-1): 136152", anchor="w", font=ctk.CTkFont(size=13))
        self.enc_lbl_phi.pack(fill="x", padx=16, pady=2)

        self.enc_lbl_d = ctk.CTkLabel(metrics_card, text="Exponente privado d: 8009", anchor="w", font=ctk.CTkFont(size=13, weight="bold"), text_color="#38bdf8")
        self.enc_lbl_d.pack(fill="x", padx=16, pady=2)

        self.enc_lbl_pubkey = ctk.CTkLabel(metrics_card, text="Llave pública (e, n): (17, 136891)", anchor="w", font=ctk.CTkFont(size=13))
        self.enc_lbl_pubkey.pack(fill="x", padx=16, pady=2)

        self.enc_lbl_padding = ctk.CTkLabel(
            metrics_card,
            text="Estado Relleno: L=3 (impar) → '+1 espacio' agregado",
            anchor="w",
            font=ctk.CTkFont(size=12),
            text_color="#fbbf24"
        )
        self.enc_lbl_padding.pack(fill="x", padx=16, pady=(4, 12))

        # Resultados de Encriptación C y L
        out_card = ctk.CTkFrame(self.tab_enc, corner_radius=8)
        out_card.pack(fill="x", padx=10, pady=(0, 10))

        out_header = ctk.CTkFrame(out_card, fg_color="transparent")
        out_header.pack(fill="x", padx=16, pady=(10, 4))

        ctk.CTkLabel(out_header, text="Mensaje Cifrado Completo (C):", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")

        btn_copy_c = ctk.CTkButton(out_header, text="Copiar C", width=80, height=26, command=lambda: self._copiar_texto(self.enc_out_c.get()))
        btn_copy_c.pack(side="right", padx=(6, 0))

        btn_transfer = ctk.CTkButton(
            out_header,
            text="Pasar a Desencriptar →",
            width=160,
            height=26,
            fg_color="#475569",
            hover_color="#334155",
            command=self.transferir_a_desencriptar
        )
        btn_transfer.pack(side="right")

        self.enc_out_c = ctk.CTkEntry(out_card, font=ctk.CTkFont(family="Consolas", size=15, weight="bold"), text_color="#38bdf8")
        self.enc_out_c.pack(fill="x", padx=16, pady=(2, 10))

        # Tabla de Detalles por Bloques
        ctk.CTkLabel(self.tab_enc, text="Detalle de Conversión por Bloques (2 caracteres cada uno):", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=12, pady=(4, 2))
        self.enc_scroll_table = ctk.CTkScrollableFrame(self.tab_enc, height=180, corner_radius=8)
        self.enc_scroll_table.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _actualizar_contador_caracteres(self, event=None):
        """Actualiza el contador de caracteres del mensaje en la pestaña de encriptación."""
        txt = self.enc_txt.get("1.0", "end-1c")
        l = len(txt)
        paridad = "par (sin relleno)" if l % 2 == 0 else "impar (+1 espacio agregado al final)"
        self.enc_len_label.configure(text=f"Longitud L: {l} caracteres · {paridad}")

    # ==========================================================================
    # PESTAÑA 2: DESENCRIPTAR
    # ==========================================================================
    def _construir_tab_desencriptar(self):
        """Construye la pestaña de desencriptación con entradas de bloques cifrados y salida."""
        top_grid = ctk.CTkFrame(self.tab_dec, fg_color="transparent")
        top_grid.pack(fill="x", padx=10, pady=10)
        top_grid.grid_columnconfigure(0, weight=3)
        top_grid.grid_columnconfigure(1, weight=2)

        # Panel izquierdo: Entradas de Desencriptación
        in_card = ctk.CTkFrame(top_grid, corner_radius=8)
        in_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)

        lbl_in_title = ctk.CTkLabel(in_card, text="Datos para Desencriptación", font=ctk.CTkFont(size=15, weight="bold"))
        lbl_in_title.pack(anchor="w", padx=16, pady=(12, 8))

        p_row = ctk.CTkFrame(in_card, fg_color="transparent")
        p_row.pack(fill="x", padx=16, pady=4)

        ctk.CTkLabel(p_row, text="Primo p:", font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self.dec_p_entry = ctk.CTkEntry(p_row, width=90, font=ctk.CTkFont(family="Consolas", size=13))
        self.dec_p_entry.grid(row=0, column=1, padx=(0, 14))

        ctk.CTkLabel(p_row, text="Primo q:", font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=2, sticky="w", padx=(0, 4))
        self.dec_q_entry = ctk.CTkEntry(p_row, width=90, font=ctk.CTkFont(family="Consolas", size=13))
        self.dec_q_entry.grid(row=0, column=3, padx=(0, 14))

        ctk.CTkLabel(p_row, text="Exponente e:", font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=4, sticky="w", padx=(0, 4))
        self.dec_e_entry = ctk.CTkEntry(p_row, width=90, font=ctk.CTkFont(family="Consolas", size=13))
        self.dec_e_entry.grid(row=0, column=5, padx=(0, 0))

        # Cifrado C y L
        c_row = ctk.CTkFrame(in_card, fg_color="transparent")
        c_row.pack(fill="x", padx=16, pady=(8, 4))

        ctk.CTkLabel(c_row, text="Mensaje Cifrado C:", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w")
        self.dec_c_entry = ctk.CTkEntry(c_row, placeholder_text="026054 123875", font=ctk.CTkFont(family="Consolas", size=14))
        self.dec_c_entry.pack(fill="x", pady=(2, 6))

        l_row = ctk.CTkFrame(in_card, fg_color="transparent")
        l_row.pack(fill="x", padx=16, pady=(2, 12))

        ctk.CTkLabel(l_row, text="Longitud original (L):", font=ctk.CTkFont(size=13, weight="bold")).pack(side="left", padx=(0, 8))
        self.dec_l_entry = ctk.CTkEntry(l_row, width=80, font=ctk.CTkFont(family="Consolas", size=13))
        self.dec_l_entry.pack(side="left")

        btn_dec = ctk.CTkButton(
            l_row,
            text="Desencriptar Mensaje",
            command=self.accion_desencriptar,
            fg_color="#059669",
            hover_color="#047857",
            font=ctk.CTkFont(weight="bold"),
            width=170
        )
        btn_dec.pack(side="right")

        # Panel derecho: Métricas de Desencriptación
        met_card = ctk.CTkFrame(top_grid, corner_radius=8)
        met_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=0)

        lbl_met_title = ctk.CTkLabel(met_card, text="Cálculo de la Llave Privada", font=ctk.CTkFont(size=15, weight="bold"))
        lbl_met_title.pack(anchor="w", padx=16, pady=(12, 8))

        self.dec_lbl_n = ctk.CTkLabel(met_card, text="Módulo n: 136891", anchor="w", font=ctk.CTkFont(size=13))
        self.dec_lbl_n.pack(fill="x", padx=16, pady=2)

        self.dec_lbl_phi = ctk.CTkLabel(met_card, text="Euler φ(n) = (p-1)(q-1): 136152", anchor="w", font=ctk.CTkFont(size=13))
        self.dec_lbl_phi.pack(fill="x", padx=16, pady=2)

        self.dec_lbl_d = ctk.CTkLabel(met_card, text="Inverso d = e⁻¹ mod φ: 8009", anchor="w", font=ctk.CTkFont(size=13, weight="bold"), text_color="#4ade80")
        self.dec_lbl_d.pack(fill="x", padx=16, pady=2)

        self.dec_lbl_privkey = ctk.CTkLabel(met_card, text="Llave privada (d, n): (8009, 136891)", anchor="w", font=ctk.CTkFont(size=13))
        self.dec_lbl_privkey.pack(fill="x", padx=16, pady=2)

        self.dec_lbl_status = ctk.CTkLabel(
            met_card,
            text="Verificación: Relleno verificado y retirado exactamente.",
            anchor="w",
            font=ctk.CTkFont(size=12),
            text_color="#4ade80"
        )
        self.dec_lbl_status.pack(fill="x", padx=16, pady=(4, 12))

        # Mensaje Recuperado
        out_card = ctk.CTkFrame(self.tab_dec, corner_radius=8)
        out_card.pack(fill="x", padx=10, pady=(0, 10))

        out_header = ctk.CTkFrame(out_card, fg_color="transparent")
        out_header.pack(fill="x", padx=16, pady=(10, 4))

        ctk.CTkLabel(out_header, text="Mensaje Original Recuperado (M):", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")

        btn_copy_m = ctk.CTkButton(out_header, text="Copiar Texto M", width=120, height=26, command=lambda: self._copiar_texto(self.dec_out_m.get()))
        btn_copy_m.pack(side="right")

        self.dec_out_m = ctk.CTkEntry(out_card, font=ctk.CTkFont(family="Consolas", size=16, weight="bold"), text_color="#4ade80")
        self.dec_out_m.pack(fill="x", padx=16, pady=(2, 10))

        # Tabla de Detalles de Desencriptación
        ctk.CTkLabel(self.tab_dec, text="Detalle de Exponenciación Inversa por Bloques (cᵈ mod n):", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=12, pady=(4, 2))
        self.dec_scroll_table = ctk.CTkScrollableFrame(self.tab_dec, height=180, corner_radius=8)
        self.dec_scroll_table.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    # ==========================================================================
    # PESTAÑA 3: ASISTENTE DE PRIMOS CON RECOMENDACIONES Y OPCIONES AVANZADAS
    # ==========================================================================
    def _construir_tab_asistente(self):
        """Construye la pestaña del asistente de parámetros primos y exponentes RSA."""
        container = ctk.CTkScrollableFrame(self.tab_helper, corner_radius=8)
        container.pack(fill="both", expand=True, padx=10, pady=10)

        # Encabezado
        ctk.CTkLabel(container, text="Asistente Dinámico de Primos y Recomendación de Parámetros RSA", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(10, 4))
        ctk.CTkLabel(
            container,
            text="Explora y genera combinaciones válidas entre 4,656 parejas de primos (126,126 < n < 1,000,000). Selecciona exponentes e compatibles y calcula el inverso d en tiempo real.",
            text_color="#94a3b8",
            font=ctk.CTkFont(size=13)
        ).pack(anchor="w", padx=16, pady=(0, 12))

        # ----------------------------------------------------------------------
        # Bloque 1: Filtro y Generación Rápida Dinámica
        # ----------------------------------------------------------------------
        gen_card = ctk.CTkFrame(container, corner_radius=8)
        gen_card.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkLabel(gen_card, text="1. Filtro por Tamaño o Estructura del Módulo n:", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=16, pady=(10, 4))

        self.filtro_tamano = ctk.CTkSegmentedButton(
            gen_card,
            values=["Todos (4,656)", "Pequeño (130K-300K)", "Mediano (300K-650K)", "Grande (650K-990K)", "Cercanos (|p-q|≤30)", "Asimétricos"],
            command=self.cambiar_filtro_categoria
        )
        self.filtro_tamano.set("Todos (4,656)")
        self.filtro_tamano.pack(fill="x", padx=16, pady=(0, 10))

        # Barra de Botones de Generación
        btn_bar = ctk.CTkFrame(gen_card, fg_color="transparent")
        btn_bar.pack(fill="x", padx=16, pady=(0, 12))

        btn_random = ctk.CTkButton(
            btn_bar,
            text="🎲 Generar Pareja Aleatoria Única",
            command=self.accion_generar_aleatorio,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=34
        )
        btn_random.pack(side="left", padx=(0, 10))

        btn_siguiente = ctk.CTkButton(
            btn_bar,
            text="➡️ Siguiente Opción Secuencial",
            command=self.accion_siguiente_sugerencia,
            fg_color=("#475569", "#334155"),
            hover_color=("#334155", "#1e293b"),
            font=ctk.CTkFont(size=13),
            height=34
        )
        btn_siguiente.pack(side="left", padx=(0, 10))

        btn_aplicar = ctk.CTkButton(
            btn_bar,
            text="✓ Aplicar Valores a Todas las Pestañas",
            command=self.accion_aplicar_sugerencia,
            fg_color="#059669",
            hover_color="#047857",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=34
        )
        btn_aplicar.pack(side="left", padx=10)

        # Presets Rápidos
        preset_bar = ctk.CTkFrame(gen_card, fg_color="transparent")
        preset_bar.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkLabel(preset_bar, text="Presets directos:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#94a3b8").pack(side="left", padx=(0, 8))

        presets = [
            ("Oficial Enunciado (367, 373, e=17)", 367, 373, 17, "Caso de Referencia del Enunciado Oficial"),
            ("Primos Gemelos (461, 463, e=17)", 461, 463, 17, "Primos Gemelos consecutivos |p-q|=2"),
            ("Asimétricos (359, 997, e=17)", 359, 997, 17, "Extremos del Rango Permitido"),
            ("Máxima Capacidad (991, 997, e=17)", 991, 997, 17, "Módulo n Máximo Cercano al Límite Superior")
        ]

        for p_label, p_val, q_val, e_val, desc in presets:
            btn_p = ctk.CTkButton(
                preset_bar,
                text=p_label,
                font=ctk.CTkFont(size=11),
                height=26,
                fg_color=("#e2e8f0", "#334155"),
                text_color=("#0f172a", "#f8fafc"),
                hover_color=("#cbd5e1", "#475569"),
                command=lambda pv=p_val, qv=q_val, ev=e_val, dv=desc: self.cargar_preset_especifico(pv, qv, ev, dv)
            )
            btn_p.pack(side="left", padx=4)

        # ----------------------------------------------------------------------
        # Bloque 2: Selección Manual Asistida con ComboBoxes
        # ----------------------------------------------------------------------
        manual_card = ctk.CTkFrame(container, corner_radius=8)
        manual_card.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkLabel(manual_card, text="2. O Selecciona Manualmente Primos de la Lista:", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=16, pady=(10, 4))
        
        manual_row = ctk.CTkFrame(manual_card, fg_color="transparent")
        manual_row.pack(fill="x", padx=16, pady=(0, 8))

        primos_disp = [str(p) for p in obtener_primos_en_rango(359, 997)]

        ctk.CTkLabel(manual_row, text="Primo p:").pack(side="left", padx=(0, 6))
        self.cbo_p = ctk.CTkComboBox(manual_row, values=primos_disp, width=100)
        self.cbo_p.set("367")
        self.cbo_p.pack(side="left", padx=(0, 16))

        ctk.CTkLabel(manual_row, text="Primo q:").pack(side="left", padx=(0, 6))
        self.cbo_q = ctk.CTkComboBox(manual_row, values=primos_disp, width=100)
        self.cbo_q.set("373")
        self.cbo_q.pack(side="left", padx=(0, 16))

        btn_eval_manual = ctk.CTkButton(
            manual_row,
            text="⚡ Validar y Calcular Pareja Manual",
            command=self.accion_calcular_manual,
            height=30,
            font=ctk.CTkFont(size=12, weight="bold")
        )
        btn_eval_manual.pack(side="left", padx=6)

        self.lbl_status_manual = ctk.CTkLabel(
            manual_card,
            text="Pareja manual lista: n = 136,891 (Válida en rango)",
            font=ctk.CTkFont(size=12),
            text_color="#38bdf8"
        )
        self.lbl_status_manual.pack(anchor="w", padx=16, pady=(0, 8))

        # ----------------------------------------------------------------------
        # Bloque 3: Parámetros Actuales y Exponentes Compatibles
        # ----------------------------------------------------------------------
        self.sugerencia_box = ctk.CTkFrame(container, corner_radius=8, fg_color=("#f1f5f9", "#1e293b"))
        self.sugerencia_box.pack(fill="x", padx=16, pady=(0, 12))

        self.lbl_sug_desc = ctk.CTkLabel(
            self.sugerencia_box,
            text="Configuración Activa: Caso de Referencia del Enunciado Oficial",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#38bdf8"
        )
        self.lbl_sug_desc.pack(anchor="w", padx=16, pady=(12, 4))

        self.lbl_sug_primos = ctk.CTkLabel(
            self.sugerencia_box,
            text="Primos seleccionados: p = 367  |  q = 373",
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold")
        )
        self.lbl_sug_primos.pack(anchor="w", padx=16, pady=2)

        self.lbl_sug_modulo = ctk.CTkLabel(
            self.sugerencia_box,
            text="Módulo n = 136891  ·  Totiente φ(n) = 136152  ·  Condición (126126 < n < 1000000): ✓ VÁLIDO",
            font=ctk.CTkFont(size=13)
        )
        self.lbl_sug_modulo.pack(anchor="w", padx=16, pady=2)

        self.lbl_sug_exp = ctk.CTkLabel(
            self.sugerencia_box,
            text="Exponente activo: e = 17  (Inverso privado d calculado: d = 8009)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#4ade80"
        )
        self.lbl_sug_exp.pack(anchor="w", padx=16, pady=(2, 6))

        # Exponentes e Chips Interactivos
        ctk.CTkLabel(
            self.sugerencia_box,
            text="Exponentes e compatibles con φ(n) (MCD=1) — Haz clic en cualquiera para seleccionarlo:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#cbd5e1"
        ).pack(anchor="w", padx=16, pady=(4, 4))

        self.frame_chips_e = ctk.CTkFrame(self.sugerencia_box, fg_color="transparent")
        self.frame_chips_e.pack(fill="x", padx=16, pady=(0, 12))

        # ----------------------------------------------------------------------
        # Bloque 4: Recomendaciones y Criterios Matemáticos Clave
        # ----------------------------------------------------------------------
        recom_card = ctk.CTkFrame(container, corner_radius=8)
        recom_card.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkLabel(recom_card, text="💡 Recomendaciones y Criterios Matemáticos Clave:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=16, pady=(12, 6))

        tips = [
            "1. Límite inferior de n (n > 126126): El bloque máximo con caracteres ASCII imprimibles es '~~' (126126). Si n fuera menor, m >= n y la reducción modular provocaría colisiones y pérdida de información.",
            "2. Límite superior de n (n < 1000000): Garantiza que cualquier bloque cifrado c = m^e mod n cumpla c < n < 1000000, permitiendo formatearlo limpiamente con exactamente 6 dígitos decimales.",
            "3. Selección del exponente e: e debe ser mayor a 1 y coprimo con φ(n) (MCD=1). Exponentes pequeños comunes como 17 o 65537 son ideales porque aceleran la exponenciación binaria sin comprometer el inverso d.",
            "4. Primos distintos (p ≠ q): Si p = q, φ(n) = p(p-1) y la estructura del criptosistema RSA colapsaría.",
        ]

        for tip in tips:
            ctk.CTkLabel(recom_card, text=tip, justify="left", wraplength=980, text_color="#cbd5e1", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=2)

        ctk.CTkLabel(recom_card, text="", height=4).pack()

        # ----------------------------------------------------------------------
        # Bloque 5: Catálogo de Primos en Rango Óptimo
        # ----------------------------------------------------------------------
        explorador_card = ctk.CTkFrame(container, corner_radius=8)
        explorador_card.pack(fill="both", expand=True, padx=16, pady=(0, 14))

        ctk.CTkLabel(explorador_card, text="Catálogo de los 97 Primos en el Rango del Proyecto [359, 997]:", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=16, pady=(10, 4))

        txt_lista_primos = ctk.CTkTextbox(explorador_card, font=ctk.CTkFont(family="Consolas", size=12), height=140)
        txt_lista_primos.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        primos_muestra = obtener_primos_en_rango(359, 997)
        lineas_primos = []
        for i in range(0, len(primos_muestra), 10):
            lineas_primos.append("  ".join(f"{p:4d}" for p in primos_muestra[i:i+10]))

        txt_lista_primos.insert("1.0", f"Total: {len(primos_muestra)} primos válidos (producen 4,656 parejas distintas con n en rango).\n" + "\n".join(lineas_primos))
        txt_lista_primos.configure(state="disabled")

        # Cargar estado inicial y renderizar chips
        self._actualizar_interfaz_sugerencia(self.sug_actual)

    def cambiar_filtro_categoria(self, valor):
        """Filtra los presets de primos según la categoría de magnitud seleccionada."""
        mapa = {
            "Todos (4,656)": "todos",
            "Pequeño (130K-300K)": "pequeno",
            "Mediano (300K-650K)": "mediano",
            "Grande (650K-990K)": "grande",
            "Cercanos (|p-q|≤30)": "cercanos",
            "Asimétricos": "asimetricos"
        }
        self.categoria_filtro_actual = mapa.get(valor, "todos")
        self.indice_sugerencia_actual = 0
        self.accion_siguiente_sugerencia()

    def accion_generar_aleatorio(self):
        """Genera y muestra una pareja aleatoria de primos válidos y su exponente."""
        sug = generar_pareja_aleatoria_libre(self.categoria_filtro_actual)
        self.sug_actual = sug
        self._actualizar_interfaz_sugerencia(sug)

    def accion_siguiente_sugerencia(self):
        """Avanza al siguiente preset o pareja sugerida de parámetros RSA."""
        sug = sugerir_parametros_rsa(categoria=self.categoria_filtro_actual, indice_variante=self.indice_sugerencia_actual)
        self.indice_sugerencia_actual += 1
        self.sug_actual = sug
        self._actualizar_interfaz_sugerencia(sug)

    def cargar_preset_especifico(self, p, q, e, desc):
        """Carga un preset específico de primos y exponente en el asistente."""
        phi = (p - 1) * (q - 1)
        d = inverso_modular(e, phi)
        exponentes = obtener_exponentes_compatibles(phi, limite=14)
        sug = {
            "p": p,
            "q": q,
            "n": p * q,
            "phi": phi,
            "e_recomendado": e,
            "d_calculado": d,
            "otros_e_compatibles": exponentes,
            "categoria": "preset",
            "descripcion": desc,
            "total_opciones_disponibles": 4656
        }
        self.sug_actual = sug
        if hasattr(self, 'cbo_p'):
            self.cbo_p.set(str(p))
            self.cbo_q.set(str(q))
        self._actualizar_interfaz_sugerencia(sug)

    def accion_calcular_manual(self):
        """Valida los primos ingresados manualmente y calcula los exponentes compatibles."""
        try:
            p = int(self.cbo_p.get().strip())
            q = int(self.cbo_q.get().strip())
        except ValueError:
            self.lbl_status_manual.configure(text="⚠️ Error: Ingrese números enteros válidos.", text_color="#ef4444")
            return

        if p == q:
            self.lbl_status_manual.configure(text="⚠️ Error: p y q deben ser distintos (p ≠ q).", text_color="#ef4444")
            return

        if not es_primo(p) or not es_primo(q):
            self.lbl_status_manual.configure(text="⚠️ Error: Tanto p como q deben ser números primos.", text_color="#ef4444")
            return

        n = p * q
        if not (126126 < n < 1000000):
            self.lbl_status_manual.configure(text=f"⚠️ Advertencia: n = {n} no cumple 126126 < n < 1000000.", text_color="#f59e0b")
            return

        phi = (p - 1) * (q - 1)
        exponentes = obtener_exponentes_compatibles(phi, limite=14)
        e = 17 if 17 in exponentes else (exponentes[0] if exponentes else 3)
        d = inverso_modular(e, phi)

        self.lbl_status_manual.configure(text=f"✓ Válido: p={p}, q={q}, n={n}, φ={phi}", text_color="#4ade80")

        sug = {
            "p": p,
            "q": q,
            "n": n,
            "phi": phi,
            "e_recomendado": e,
            "d_calculado": d,
            "otros_e_compatibles": exponentes,
            "categoria": "manual",
            "descripcion": f"Selección manual asistida (p={p}, q={q}, n={n})",
            "total_opciones_disponibles": 4656
        }
        self.sug_actual = sug
        self._actualizar_interfaz_sugerencia(sug)

    def seleccionar_exponente_chip(self, e_elegido):
        """Selecciona un exponente público desde los botones rápidos y actualiza la vista."""
        phi = self.sug_actual["phi"]
        d = inverso_modular(e_elegido, phi)
        self.sug_actual["e_recomendado"] = e_elegido
        self.sug_actual["d_calculado"] = d
        self._actualizar_interfaz_sugerencia(self.sug_actual)

    def _actualizar_interfaz_sugerencia(self, sug):
        """Actualiza los indicadores y etiquetas del asistente con la sugerencia actual."""
        self.lbl_sug_desc.configure(text=f"Configuración: {sug.get('descripcion', '')}")
        self.lbl_sug_primos.configure(text=f"Primos seleccionados: p = {sug['p']}  |  q = {sug['q']}")
        
        n = sug['n']
        rango_ok = "✓ VÁLIDO EN RANGO" if 126126 < n < 1000000 else "⚠️ FUERA DE RANGO"
        self.lbl_sug_modulo.configure(text=f"Módulo n = {n}  ·  Totiente φ(n) = {sug['phi']}  ·  Condición (126126 < n < 1000000): {rango_ok}")
        self.lbl_sug_exp.configure(text=f"Exponente activo: e = {sug['e_recomendado']}  (Inverso privado d calculado: {sug['d_calculado']})")

        # Actualizar ComboBoxes manuales si están disponibles
        if hasattr(self, 'cbo_p'):
            self.cbo_p.set(str(sug["p"]))
            self.cbo_q.set(str(sug["q"]))

        # Renderizar chips interactivos de exponentes e
        if hasattr(self, 'frame_chips_e'):
            for widget in self.frame_chips_e.winfo_children():
                widget.destroy()

            exponentes = list(sug.get("otros_e_compatibles", []))
            if sug["e_recomendado"] not in exponentes:
                exponentes.insert(0, sug["e_recomendado"])

            for exp in exponentes[:14]:
                es_activo = (exp == sug["e_recomendado"])
                btn_chip = ctk.CTkButton(
                    self.frame_chips_e,
                    text=f"✓ e = {exp}" if es_activo else f"e = {exp}",
                    font=ctk.CTkFont(size=12, weight="bold" if es_activo else "normal"),
                    width=78,
                    height=28,
                    fg_color="#059669" if es_activo else ("#e2e8f0", "#334155"),
                    hover_color="#047857" if es_activo else ("#cbd5e1", "#475569"),
                    text_color="#ffffff" if es_activo else ("#0f172a", "#f8fafc"),
                    command=lambda ev=exp: self.seleccionar_exponente_chip(ev)
                )
                btn_chip.pack(side="left", padx=4, pady=2)

    def accion_aplicar_sugerencia(self):
        """Aplica los parámetros seleccionados en el asistente a las pestañas de cifrado."""
        sug = self.sug_actual

        self.enc_p_entry.delete(0, "end")
        self.enc_p_entry.insert(0, str(sug["p"]))
        self.enc_q_entry.delete(0, "end")
        self.enc_q_entry.insert(0, str(sug["q"]))
        self.enc_e_entry.delete(0, "end")
        self.enc_e_entry.insert(0, str(sug["e_recomendado"]))

        self.dec_p_entry.delete(0, "end")
        self.dec_p_entry.insert(0, str(sug["p"]))
        self.dec_q_entry.delete(0, "end")
        self.dec_q_entry.insert(0, str(sug["q"]))
        self.dec_e_entry.delete(0, "end")
        self.dec_e_entry.insert(0, str(sug["e_recomendado"]))

        self.trace_p.delete(0, "end")
        self.trace_p.insert(0, str(sug["p"]))
        self.trace_q.delete(0, "end")
        self.trace_q.insert(0, str(sug["q"]))
        self.trace_e.delete(0, "end")
        self.trace_e.insert(0, str(sug["e_recomendado"]))

        self.accion_encriptar(silencioso=True)
        self.actualizar_desglose_matematico()
        messagebox.showinfo(
            "Parámetros Aplicados con Éxito",
            f"Se han cargado a todas las pestañas los parámetros:\n\n"
            f"• Primo p = {sug['p']}\n"
            f"• Primo q = {sug['q']}\n"
            f"• Módulo n = {sug['n']}\n"
            f"• Totiente φ(n) = {sug['phi']}\n"
            f"• Exponente público e = {sug['e_recomendado']}\n"
            f"• Clave privada d = {sug['d_calculado']}\n\n"
            f"Los módulos de Encriptación, Desencriptación y Desglose Matemático han sido actualizados."
        )

    # ==========================================================================
    # PESTAÑA 4: DESGLOSE MATEMÁTICO PASO A PASO
    # ==========================================================================
    def _construir_tab_desglose(self):
        """Construye la pestaña de desglose matemático paso a paso."""
        card = ctk.CTkFrame(self.tab_trace, corner_radius=8)
        card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(card, text="Desglose Matemático y Traza Completa de Cálculos", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(
            card,
            text="Visualiza con exactitud cómo se ejecutaron las operaciones: divisiones sucesivas de Euclides, matrices del Algoritmo Extendido de Bézout y verificación del inverso d.",
            text_color="#94a3b8",
            font=ctk.CTkFont(size=13)
        ).pack(anchor="w", padx=16, pady=(0, 10))

        # Entradas para la traza
        in_row = ctk.CTkFrame(card, fg_color="transparent")
        in_row.pack(fill="x", padx=16, pady=4)

        ctk.CTkLabel(in_row, text="Primo p:").grid(row=0, column=0, padx=(0, 4))
        self.trace_p = ctk.CTkEntry(in_row, width=80)
        self.trace_p.insert(0, "367")
        self.trace_p.grid(row=0, column=1, padx=(0, 12))
        self.trace_p.bind("<KeyRelease>", self.actualizar_desglose_matematico)

        ctk.CTkLabel(in_row, text="Primo q:").grid(row=0, column=2, padx=(0, 4))
        self.trace_q = ctk.CTkEntry(in_row, width=80)
        self.trace_q.insert(0, "373")
        self.trace_q.grid(row=0, column=3, padx=(0, 12))
        self.trace_q.bind("<KeyRelease>", self.actualizar_desglose_matematico)

        ctk.CTkLabel(in_row, text="Exponente e:").grid(row=0, column=4, padx=(0, 4))
        self.trace_e = ctk.CTkEntry(in_row, width=80)
        self.trace_e.insert(0, "17")
        self.trace_e.grid(row=0, column=5, padx=(0, 16))
        self.trace_e.bind("<KeyRelease>", self.actualizar_desglose_matematico)

        btn_recalc = ctk.CTkButton(
            in_row,
            text="Recalcular Desglose",
            width=140,
            command=self.actualizar_desglose_matematico,
            fg_color="#475569",
            hover_color="#334155"
        )
        btn_recalc.grid(row=0, column=6)

        self.trace_textbox = ctk.CTkTextbox(card, font=ctk.CTkFont(family="Consolas", size=12), height=400)
        self.trace_textbox.pack(fill="both", expand=True, padx=16, pady=14)

    def actualizar_desglose_matematico(self, event=None):
        """Recalcula y muestra el desglose matemático paso a paso para p, q y e."""
        try:
            p = int(self.trace_p.get().strip())
            q = int(self.trace_q.get().strip())
            e = int(self.trace_e.get().strip())

            info = desglosar_calculos_paso_a_paso(p, q, e)

            lineas = [
                "=========================================================================================",
                "                DESGLOSE MATEMÁTICO COMPLETO Y PASO A PASO (ALGORITMOS PROPIOS)",
                "=========================================================================================",
                f"1. VERIFICACIÓN DE PRIMALIDAD Y PARÁMETROS BÁSICOS",
                f"   • p = {p}: {'Es primo ✓' if info['p_es_primo'] else 'NO ES PRIMO ✗'}",
                f"   • q = {q}: {'Es primo ✓' if info['q_es_primo'] else 'NO ES PRIMO ✗'}",
                f"   • Primos distintos: {'p ≠ q ✓' if info['primos_distintos'] else 'p y q son iguales ✗'}",
                "",
                f"2. CÁLCULO DEL MÓDULO n Y CONDICIÓN DE TAMAÑO",
                f"   • n = p × q = {p} × {q} = {info['n']}",
                f"   • Verificación de intervalo: 126126 < {info['n']} < 1000000: {'EN RANGO PERMITIDO ✓' if info['n_en_rango'] else 'FUERA DE RANGO ✗'}",
                f"   • Función Totiente de Euler: φ(n) = (p - 1)(q - 1) = ({p - 1}) × ({q - 1}) = {info['phi']}",
                "",
                f"3. ALGORITMO DE EUCLIDES PARA VALIDAR COPRIMALIDAD: MCD(e, φ(n))",
                f"   • Se calculan divisiones sucesivas con e = {e} y φ = {info['phi']}:"
            ]

            for idx, paso in enumerate(info["pasos_euclides"], 1):
                lineas.append(f"     Paso {idx}: {paso['dividendo']:6d} = {paso['divisor']:6d} × ({paso['cociente']:4d}) + {paso['residuo']:6d}")

            lineas.append(f"   • Último residuo no nulo = {info['mcd']}  →  MCD({e}, {info['phi']}) = {info['mcd']}")
            lineas.append(f"   • Estado: {'COPRIMOS CONFIRMADOS ✓ (e es válido)' if info['es_coprimo'] else 'NO SON COPRIMOS ✗ (e no es válido)'}")
            lineas.append("")

            lineas.append("4. ALGORITMO EXTENDIDO DE EUCLIDES (MÉTODO MATRICIAL DE BÉZOUT)")
            lineas.append("   • Se realiza el seguimiento matricial M_k = [M_{k-1}, M_{k-2} - q_k * M_{k-1}]:")
            lineas.append("     Paso | Dividendo | Divisor | Cociente | Residuo | Coeficiente s (para e) | Coeficiente t (para φ)")
            lineas.append("     " + "-" * 80)

            for paso in info["pasos_bezout"]:
                lineas.append(
                    f"       {paso['paso']:2d} | {paso['dividendo']:9d} | {paso['divisor']:7d} | {paso['cociente']:8d} | {paso['residuo']:7d} | "
                    f"s = {paso['coef_s']:10d} | t = {paso['coef_t']:10d}"
                )

            lineas.append("")
            lineas.append(f"   • Identidad de Bézout obtenida: {info['ecuacion_bezout']}")
            lineas.append(f"   • Coeficiente asociado a e: s = {info['coeficiente_s']}")
            lineas.append("")

            lineas.append("5. OBTENCIÓN DEL EXPONENTE PRIVADO d")
            lineas.append(f"   • Como ed ≡ 1 (mod φ), d es el representante positivo de s módulo φ:")
            lineas.append(f"     d = s mod φ = {info['coeficiente_s']} mod {info['phi']} = {info['d_calculado']}")
            lineas.append(f"   • Rango de d: 1 ≤ d < φ ({1} ≤ {info['d_calculado']} < {info['phi']})")
            lineas.append("")

            lineas.append("6. VERIFICACIÓN FINAL DE LA LLAVE")
            lineas.append(f"   • Llave Pública generada:  (e, n) = ({e}, {info['n']})")
            lineas.append(f"   • Llave Privada generada:  (d, n) = ({info['d_calculado']}, {info['n']})")
            lineas.append(f"   • Comprobación de congruencia: {info['verificacion_modular']}  {'✓ [IDENTIDAD VERIFICADA]' if info['verificacion_ok'] else '✗ [ERROR EN INVERSO]'}")
            lineas.append("=========================================================================================")

            self.trace_textbox.delete("1.0", "end")
            self.trace_textbox.insert("1.0", "\n".join(lineas))

        except Exception as ex:
            self.trace_textbox.delete("1.0", "end")
            self.trace_textbox.insert("1.0", f"Error al generar desglose de cálculos: {ex}\nVerifica que p, q y e sean números enteros válidos.")

    # ==========================================================================
    # PESTAÑA 5: INSTRUCCIONES Y PASOS A SEGUIR (NUEVO MÓDULO)
    # ==========================================================================
    def _construir_tab_instrucciones(self):
        """Construye la pestaña con la guía rápida de uso de la aplicación."""
        container = ctk.CTkScrollableFrame(self.tab_guide, corner_radius=8)
        container.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(container, text="Guía de Uso, Instrucciones y Pasos a Seguir", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(10, 4))
        ctk.CTkLabel(
            container,
            text="Sigue estos pasos para utilizar el criptosistema correctamente y preparar la grabación del video demostrativo.",
            text_color="#94a3b8",
            font=ctk.CTkFont(size=13)
        ).pack(anchor="w", padx=16, pady=(0, 14))

        secciones = [
            ("Paso 1: Configurar los Parámetros RSA (p, q, e)", [
                "• Puedes pulsar en cualquier momento el botón superior 'Cargar Caso de RSA' para cargar los valores del enunciado (p=367, q=373, e=17).",
                "• O bien, ve a la pestaña 'Asistente de Primos' para generar nuevas parejas que cumplan automáticamente el rango 126126 < n < 1000000 y presiona 'Aplicar Valores'.",
                "• Si introduces valores manuales, asegúrate de que p y q sean primos distintos y que MCD(e, φ) = 1."
            ]),
            ("Paso 2: Encriptar un Mensaje de Texto", [
                "• Escribe el texto en la caja 'Mensaje original (M)'. Se admiten mayúsculas, minúsculas, espacios, signos y números ASCII (códigos 32 al 126).",
                "• Observa el contador: si la longitud L es impar, el sistema añadirá automáticamente un espacio al final como relleno.",
                "• Pulsa 'Encriptar Mensaje'. Obtendrás el mensaje cifrado C (bloques de 6 dígitos), la longitud original L y la tabla detallada de cada bloque.",
                "• Puedes usar el botón 'Pasar a Desencriptar →' para transferir C, L, p, q y e automáticamente a la siguiente pestaña."
            ]),
            ("Paso 3: Desencriptar y Recuperar el Mensaje Original", [
                "• Ingresa el mensaje cifrado C (los bloques de 6 dígitos separados por espacios) y la longitud original L.",
                "• Pulsa 'Desencriptar Mensaje'. El sistema calculará el inverso modular d y aplicará m ≡ c^d (mod n).",
                "• Verificación de relleno: Si L era impar, comprobará que el último carácter sea un espacio y retirará exactamente ese carácter, conservando intactos todos los espacios originales del mensaje."
            ]),
            ("Paso 4: Auditoría y Comprobación de Cálculos", [
                "• En la pestaña 'Desglose Matemático' puedes observar en tiempo real la traza del Algoritmo de Euclides (divisiones sucesivas) y de Bézout matricial.",
                "• En la pestaña 'Auditoría de Código' puedes revisar directamente el código fuente propio que implementa los algoritmos sin librerías externas."
            ]),
            ("Guía Rápida para la Grabación del Video Demostrativo", [
                "1. Inicio: Muestra la pantalla inicial y pulsa 'Cargar Caso de RSA' para verificar el caso de prueba oficial.",
                "2. Encriptación: Encripta un mensaje (por ejemplo 'RSA' o un texto con espacios) y muestra la tabla con los bloques generados.",
                "3. Desencriptación: Pasa los datos a desencriptar y muestra cómo se recupera exactamente el mensaje original.",
                "4. Prueba de Validación/Error: Intenta ingresar un valor no primo (ej. p=368) o un carácter no admitido (ej. una 'ñ' o tilde) para mostrar el mensaje de validación amigable sin cierres inesperados.",
                "5. Desglose: Muestra brevemente la pestaña 'Desglose Matemático' para evidenciar los cálculos de Euclides y Bézout."
            ]),
        ]

        for titulo, items in secciones:
            sec_card = ctk.CTkFrame(container, corner_radius=8)
            sec_card.pack(fill="x", padx=16, pady=6)

            ctk.CTkLabel(sec_card, text=titulo, font=ctk.CTkFont(size=14, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=16, pady=(10, 4))
            for item in items:
                ctk.CTkLabel(sec_card, text=item, justify="left", wraplength=980, font=ctk.CTkFont(size=12)).pack(anchor="w", padx=20, pady=2)
            ctk.CTkLabel(sec_card, text="", height=4).pack()

    # ==========================================================================
    # PESTAÑA 6: AUDITORÍA DE CÓDIGO Y ALGORITMOS
    # ==========================================================================
    def _construir_tab_auditoria(self):
        """Construye la pestaña de auditoría y ejecución de pruebas unitarias."""
        card = ctk.CTkFrame(self.tab_audit, corner_radius=8)
        card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(card, text="Auditoría de Algoritmos Propios Implementados", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(
            card,
            text="Cumplimiento estricto del enunciado: no se utilizó math.gcd, pow() modular de 3 argumentos ni librerías externas.",
            text_color="#94a3b8",
            font=ctk.CTkFont(size=13)
        ).pack(anchor="w", padx=16, pady=(0, 12))

        txt_audit = ctk.CTkTextbox(card, font=ctk.CTkFont(family="Consolas", size=12))
        txt_audit.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        codigo_resumen = """
1. MÁXIMO COMÚN DIVISOR (Algoritmo Clásico de Euclides por Divisiones Sucesivas)
---------------------------------------------------------------------------------
def mcd_euclides(a: int, b: int) -> int:
    a_abs, b_abs = abs(a), abs(b)
    while b_abs != 0:
        a_abs, b_abs = b_abs, a_abs % b_abs
    return a_abs


2. INVERSO MODULAR (Algoritmo Extendido de Euclides - Formulación Matricial de Bézout)
---------------------------------------------------------------------------------
def bezout_matricial(a: int, b: int) -> tuple[int, int]:
    m = [[1, 0], [0, 1]]
    r0, r1 = a, b
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 % r1
        m = [m[1], [m[0][0] - q * m[1][0], m[0][1] - q * m[1][1]]]
    return (m[0][0], m[0][1])

def inverso_modular(e: int, phi: int) -> int:
    s, _ = bezout_matricial(e, phi)
    d = s % phi
    if d < 1:
        d += phi
    return d


3. EXPONENCIACIÓN MODULAR BINARIA (Cuadrados Repetidos Reduciendo Módulo n)
---------------------------------------------------------------------------------
def exponenciacion_modular(base: int, exp: int, mod: int) -> int:
    resultado = 1
    base_actual = base % mod
    potencia = exp
    while potencia > 0:
        if potencia % 2 == 1:
            resultado = (resultado * base_actual) % mod
        base_actual = (base_actual * base_actual) % mod
        potencia //= 2
    return resultado
"""
        txt_audit.insert("1.0", codigo_resumen.strip())
        txt_audit.configure(state="disabled")

    # ==========================================================================
    # CONTROLADORES DE ACCIÓN
    # ==========================================================================
    def toggle_theme(self):
        """Alterna entre el modo visual claro y oscuro de la interfaz."""
        mode = self.theme_switch.get()
        ctk.set_appearance_mode(mode)

    def cargar_caso_referencia(self, ejecutar_inicial=False):
        """Carga el caso de referencia del enunciado (p=367, q=373, e=17, mensaje=RSA)."""
        # Valores del PDF: p=367, q=373, e=17, M="RSA"
        self.enc_p_entry.delete(0, "end")
        self.enc_p_entry.insert(0, "367")
        self.enc_q_entry.delete(0, "end")
        self.enc_q_entry.insert(0, "373")
        self.enc_e_entry.delete(0, "end")
        self.enc_e_entry.insert(0, "17")
        self.enc_txt.delete("1.0", "end")
        self.enc_txt.insert("1.0", "RSA")

        self.dec_p_entry.delete(0, "end")
        self.dec_p_entry.insert(0, "367")
        self.dec_q_entry.delete(0, "end")
        self.dec_q_entry.insert(0, "373")
        self.dec_e_entry.delete(0, "end")
        self.dec_e_entry.insert(0, "17")
        self.dec_c_entry.delete(0, "end")
        self.dec_c_entry.insert(0, "026054 123875")
        self.dec_l_entry.delete(0, "end")
        self.dec_l_entry.insert(0, "3")

        self.trace_p.delete(0, "end")
        self.trace_p.insert(0, "367")
        self.trace_q.delete(0, "end")
        self.trace_q.insert(0, "373")
        self.trace_e.delete(0, "end")
        self.trace_e.insert(0, "17")

        self._actualizar_contador_caracteres()
        self.actualizar_desglose_matematico()
        self.accion_encriptar(silencioso=ejecutar_inicial)

    def accion_encriptar(self, silencioso=False):
        """Ejecuta la encriptación RSA del mensaje actual y muestra los bloques resultantes."""
        try:
            p = int(self.enc_p_entry.get().strip())
            q = int(self.enc_q_entry.get().strip())
            e = int(self.enc_e_entry.get().strip())
            mensaje = self.enc_txt.get("1.0", "end-1c")

            if not mensaje and not silencioso:
                messagebox.showwarning("Atención", "Ingresa un mensaje para encriptar.")
                return

            res = encriptar_mensaje(mensaje, p, q, e)

            # Actualizar tarjetas de métricas
            self.enc_lbl_n.configure(text=f"Módulo n = p × q: {res['n']}  (Válido)")
            self.enc_lbl_phi.configure(text=f"Euler φ(n) = (p-1)(q-1): {res['phi']}")
            self.enc_lbl_d.configure(text=f"Exponente privado d: {res['d']}")
            self.enc_lbl_pubkey.configure(text=f"Llave pública (e, n): ({res['e']}, {res['n']})")

            padding_txt = f"Estado Relleno: L={res['L']} (impar) → '+1 espacio' agregado al final" if res['hubo_relleno'] else f"Estado Relleno: L={res['L']} (par) → Sin relleno"
            self.enc_lbl_padding.configure(text=padding_txt)

            # Salida de Cifrado C
            self.enc_out_c.delete(0, "end")
            self.enc_out_c.insert(0, res["mensaje_cifrado_C"])

            # Renderizar tabla por bloques
            self._renderizar_tabla_bloques(self.enc_scroll_table, res["detalle_pasos"], modo="enc", e=res["e"], n=res["n"])

        except Exception as ex:
            if not silencioso:
                messagebox.showerror("Error de Validación en Encriptación", str(ex))

    def accion_desencriptar(self):
        """Ejecuta la desencriptación RSA de los bloques cifrados y muestra el texto recuperado."""
        try:
            p = int(self.dec_p_entry.get().strip())
            q = int(self.dec_q_entry.get().strip())
            e = int(self.dec_e_entry.get().strip())
            c = self.dec_c_entry.get().strip()
            l = int(self.dec_l_entry.get().strip())

            res = desencriptar_mensaje(c, l, p, q, e)

            self.dec_lbl_n.configure(text=f"Módulo n: {res['n']}")
            self.dec_lbl_phi.configure(text=f"Euler φ(n) = (p-1)(q-1): {res['phi']}")
            self.dec_lbl_d.configure(text=f"Inverso d = e⁻¹ mod φ: {res['d']}")
            self.dec_lbl_privkey.configure(text=f"Llave privada (d, n): ({res['d']}, {res['n']})")

            relleno_txt = f"Relleno verificado: L={res['L']} es impar → Espacio final retirado con éxito" if res['hubo_relleno'] else f"Relleno verificado: L={res['L']} es par → Sin relleno"
            self.dec_lbl_status.configure(text=relleno_txt)

            # Salida Mensaje M
            self.dec_out_m.delete(0, "end")
            self.dec_out_m.insert(0, res["mensaje_recuperado"])

            # Renderizar tabla
            self._renderizar_tabla_bloques(self.dec_scroll_table, res["detalle_pasos"], modo="dec", d=res["d"], n=res["n"])

        except Exception as ex:
            messagebox.showerror("Error de Validación en Desencriptación", str(ex))

    def _renderizar_tabla_bloques(self, container, pasos: List[Dict[str, Any]], modo="enc", e=0, d=0, n=0):
        """Renderiza la tabla detallada de bloques procesados en encriptación o desencriptación."""
        # Limpiar tabla previa
        for widget in container.winfo_children():
            widget.destroy()

        # Encabezados
        header_frame = ctk.CTkFrame(container, fg_color=("#cbd5e1", "#334155"), corner_radius=4)
        header_frame.pack(fill="x", pady=(0, 4))
        header_frame.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        cols = ["# Bloque", "Pareja Caracteres", "ASCII (3 dígitos)", "Bloque m (6d)", "Fórmula Modular", "Cifrado c (6d)"] if modo == "enc" else ["# Bloque", "Bloque Cifrado c", "Fórmula Modular cᵈ", "Bloque m (6d)", "ASCII (3 dígitos)", "Caracteres"]

        for idx, col in enumerate(cols):
            ctk.CTkLabel(header_frame, text=col, font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=idx, padx=6, pady=6)

        # Filas
        for row_idx, paso in enumerate(pasos):
            row_frame = ctk.CTkFrame(container, fg_color=("transparent" if row_idx % 2 == 0 else ("#f1f5f9", "#1e293b")), corner_radius=4)
            row_frame.pack(fill="x", pady=1)
            row_frame.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

            if modo == "enc":
                c1 = repr(paso["pareja_caracteres"][0])
                c2 = repr(paso["pareja_caracteres"][1])
                valores = [
                    str(paso["indice_bloque"]),
                    f"{c1} y {c2}",
                    f"{paso['codigos_ascii'][0]:03d}, {paso['codigos_ascii'][1]:03d}",
                    paso["bloque_texto_6d"],
                    f"{paso['m_numerico']}^{e} mod {n}",
                    paso["c_formateado_6d"]
                ]
            else:
                c1 = repr(paso["caracteres"][0])
                c2 = repr(paso["caracteres"][1])
                valores = [
                    str(paso["indice_bloque"]),
                    paso["c_str"],
                    f"{paso['c_val']}^{d} mod {n}",
                    paso["m_str_6d"],
                    f"{paso['codigos_ascii'][0]:03d}, {paso['codigos_ascii'][1]:03d}",
                    f"{c1} y {c2}"
                ]

            for col_idx, val in enumerate(valores):
                ctk.CTkLabel(row_frame, text=val, font=ctk.CTkFont(family="Consolas", size=12)).grid(row=0, column=col_idx, padx=4, pady=4)

    def transferir_a_desencriptar(self):
        """Copia los parámetros y el texto cifrado hacia la pestaña de desencriptación."""
        c = self.enc_out_c.get().strip()
        p = self.enc_p_entry.get().strip()
        q = self.enc_q_entry.get().strip()
        e = self.enc_e_entry.get().strip()
        msg = self.enc_txt.get("1.0", "end-1c")
        l = len(msg)

        self.dec_c_entry.delete(0, "end")
        self.dec_c_entry.insert(0, c)
        self.dec_l_entry.delete(0, "end")
        self.dec_l_entry.insert(0, str(l))
        self.dec_p_entry.delete(0, "end")
        self.dec_p_entry.insert(0, p)
        self.dec_q_entry.delete(0, "end")
        self.dec_q_entry.insert(0, q)
        self.dec_e_entry.delete(0, "end")
        self.dec_e_entry.insert(0, e)

        self.tabview.set("  Desencriptar Mensaje  ")
        self.accion_desencriptar()

    def _copiar_texto(self, texto: str):
        """Copia el texto indicado al portapapeles del sistema."""
        if not texto:
            return
        self.clipboard_clear()
        self.clipboard_append(texto)
        messagebox.showinfo("Copiado", "Texto copiado al portapapeles con éxito.")


def main():
    """Crea e inicia el bucle principal de la aplicación gráfica."""
    app = AppCriptografiaRSA()
    app.mainloop()


if __name__ == "__main__":
    main()
