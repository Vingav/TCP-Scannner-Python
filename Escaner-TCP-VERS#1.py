"""
Escáner de Puertos - Versión #1 sin dependencias externas

Este script realiza un escaneo de puertos TCP sobre un objetivo (IP o dominio)
usando solo módulos de la biblioteca estándar de Python. Ofrece salida en formato
tabla, JSON o CSV. Es ideal para quienes desean herramientas simples, auditables
y fáciles de portar sin instalar librerías adicionales. Se aceptan sugerencias y aportes

Autor: Josue Ramirez / GitHub Josubks
Fecha: 2025
"""

import socket  # Para la conexión de red
import argparse  # Para parseo de argumentos desde la consola
from concurrent.futures import ThreadPoolExecutor, as_completed  # Escaneo en paralelo
import sys  # Para salida de errores
import errno  # Para traducir errores de red
import os  # Para obtener cantidad de CPUs
import json  # Para exportar resultados en JSON


# Clase principal para gestionar el escaneo de puertos
class EscanerPuertos:
    def __init__(self, objetivo, puertos, tiempo_espera=1, max_hilos=None):
        """
        Inicializa el escáner con parámetros básicos.
        - objetivo: IP o dominio a escanear
        - puertos: lista de puertos a escanear
        - tiempo_espera: timeout por intento (en segundos)
        - max_hilos: número de hilos (por defecto: 4 x núcleos)
        """
        self.objetivo = objetivo
        self.puertos = puertos
        self.tiempo_espera = tiempo_espera
        self.max_hilos = max_hilos or os.cpu_count() * 4
        self.resultados = {}

    def validar_objetivo(self):
        """
        Verifica si el objetivo es válido (IP o hostname resoluble).
        """
        try:
            socket.inet_aton(self.objetivo)  # Validar como IP
            return True
        except socket.error:
            try:
                socket.gethostbyname(self.objetivo)  # Validar como dominio
                return True
            except socket.error:
                return False

    def escanear_puerto(self, puerto):
        """
        Intenta conectarse al puerto indicado. Devuelve estado y posible error.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.tiempo_espera)
                resultado = s.connect_ex((self.objetivo, puerto))

                if resultado == 0:
                    return (puerto, "abierto")
                else:
                    mensaje_error = os.strerror(resultado) if resultado in errno.errorcode else "cerrado"
                    return (puerto, f"cerrado ({mensaje_error})")

        except socket.timeout:
            return (puerto, "filtrado (timeout)")
        except Exception as e:
            return (puerto, f"error ({str(e)})")

    def ejecutar_escaneo(self):
        """
        Ejecuta el escaneo usando múltiples hilos y retorna resultados.
        """
        if not self.validar_objetivo():
            raise ValueError("Objetivo inválido")

        with ThreadPoolExecutor(max_workers=self.max_hilos) as ejecutor:
            futuros = {ejecutor.submit(self.escanear_puerto, puerto): puerto for puerto in self.puertos}

            for futuro in as_completed(futuros):
                puerto, estado = futuro.result()
                self.resultados[puerto] = estado

        return self.resultados


# Clase para formatear la salida en diferentes formatos: tabla, csv o json
class FormateadorSalida:
    @staticmethod
    def generar_resultados(resultados, formato="tabla"):
        if formato == "json":
            return FormateadorSalida._generar_json(resultados)
        elif formato == "csv":
            return FormateadorSalida._generar_csv(resultados)
        else:
            return FormateadorSalida._generar_tabla(resultados)

    @staticmethod
    def _generar_tabla(resultados):
        """
        Devuelve una tabla de puertos con estado y posible servicio.
        """
        cabecera = ["Puerto", "Estado", "Servicio"]
        filas = []

        for puerto, estado in sorted(resultados.items()):
            try:
                servicio = socket.getservbyport(puerto, "tcp") if "abierto" in estado else "-"
            except:
                servicio = "desconocido"
            filas.append([str(puerto), estado, servicio])

        anchos = [max(len(str(x)) for x in col) for col in zip(cabecera, *filas)]

        tabla = []
        separador = "+".join(["-" * (ancho + 2) for ancho in anchos])
        tabla.append(separador)
        tabla.append("|".join([f" {cabecera[i].ljust(anchos[i])} " for i in range(len(cabecera))]))
        tabla.append(separador)

        for fila in filas:
            tabla.append("|".join([f" {str(fila[i]).ljust(anchos[i])} " for i in range(len(fila))]))

        tabla.append(separador)
        return "\n".join(tabla)

    @staticmethod
    def _generar_csv(resultados):
        """
        Devuelve los resultados en formato CSV.
        """
        csv = "Puerto,Estado,Servicio\n"
        for puerto, estado in sorted(resultados.items()):
            try:
                servicio = socket.getservbyport(puerto, "tcp") if "abierto" in estado else "-"
            except:
                servicio = "desconocido"
            csv += f"{puerto},{estado},{servicio}\n"
        return csv

    @staticmethod
    def _generar_json(resultados):
        """
        Devuelve los resultados en formato JSON (con indentación).
        """
        data = {}
        for puerto, estado in resultados.items():
            try:
                servicio = socket.getservbyport(puerto, "tcp") if "abierto" in estado else None
            except:
                servicio = "desconocido"
            data[str(puerto)] = {"estado": estado, "servicio": servicio}
        return json.dumps(data, indent=2)


def analizar_argumentos():
    """
    Define y analiza los argumentos de línea de comandos.
    """
    parser = argparse.ArgumentParser(
        description="Escáner de Puertos - Versión sin dependencias externas",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("objetivo", help="Dirección IP o dominio a escanear")
    parser.add_argument("-p", "--puertos", help="Rango de puertos (ej: 1-1000)", default="1-1024")
    parser.add_argument("-t", "--tiempo-espera", type=float, help="Tiempo de espera por puerto (segundos)", default=1.5)
    parser.add_argument("-o", "--formato-salida", choices=["tabla", "json", "csv"], default="tabla", help="Formato de salida")
    return parser.parse_args()


def parsear_rango_puertos(rango):
    """
    Parsea un rango de puertos como "20-80" o un único puerto "443".
    """
    try:
        if '-' in rango:
            inicio, fin = map(int, rango.split('-'))
            if inicio > fin or inicio < 1 or fin > 65535:
                raise ValueError("Rango inválido")
            return list(range(inicio, fin + 1))
        else:
            puerto = int(rango)
            if puerto < 1 or puerto > 65535:
                raise ValueError("Puerto fuera de rango")
            return [puerto]
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Rango de puertos inválido: {e}")


def main():
    """
    Función principal que orquesta el flujo completo del escaneo.
    """
    args = analizar_argumentos()
    puertos = parsear_rango_puertos(args.puertos)

    escaner = EscanerPuertos(
        objetivo=args.objetivo,
        puertos=puertos,
        tiempo_espera=args.tiempo_espera
    )

    try:
        resultados = escaner.ejecutar_escaneo()
        salida = FormateadorSalida.generar_resultados(resultados, args.formato_salida)
        print(salida)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)


# Ejecuta el script si es llamado desde la terminal
if __name__ == "__main__":
    main()
