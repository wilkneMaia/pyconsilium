#!/usr/bin/env python3
"""
Exemplo de uso do Gerenciador de Senhas com arquivo de chave mestra
"""

import sys
import os

sys.path.append(os.path.dirname(__file__))

from app_improved import ImprovedPasswordManager


def exemplo_uso():
    print("🔐 Exemplo de Uso - Gerenciador de Senhas com Chave Automática")
    print("=" * 70)

    try:
        # Inicializa o gerenciador (chave será carregada/criada automaticamente)
        print("📝 Inicializando gerenciador...")
        manager = ImprovedPasswordManager()
        print("✅ Gerenciador inicializado!")

        # Adiciona algumas senhas de exemplo
        print("\n➕ Adicionando senhas de exemplo...")

        senhas_exemplo = [
            (
                "Gmail",
                "usuario@gmail.com",
                "MinhaSenh@123!",
                "Conta principal do Gmail",
            ),
            ("Facebook", "meu.usuario", "F@cebook2024!", "Rede social"),
            ("GitHub", "dev_user", "GitHub#Dev2024", "Repositórios de código"),
        ]

        for service, username, password, notes in senhas_exemplo:
            success, message = manager.add_password(service, username, password, notes)
            print(f"  {service}: {'✅' if success else '❌'} {message}")

        # Busca uma senha específica
        print("\n🔍 Buscando senha específica...")
        password, message = manager.get_password("Gmail", "usuario@gmail.com")
        if password:
            print(f"✅ {message}")
            print(f"   Senha encontrada: {password}")
        else:
            print(f"❌ {message}")

        # Busca por texto
        print("\n🔍 Buscando por texto 'gmail'...")
        results = manager.search_passwords("gmail")
        print(f"✅ {len(results)} resultado(s) encontrado(s):")
        for pwd in results:
            print(f"   • {pwd.service} - {pwd.username}")

        # Relatório de força
        print("\n📊 Relatório de força das senhas...")
        report = manager.get_strength_report()
        print(f"Total de senhas: {report['total']}")
        print("Distribuição por força:")
        for level, count in report["strength_distribution"].items():
            percentage = (count / report["total"]) * 100 if report["total"] > 0 else 0
            print(f"  {level}: {count} ({percentage:.1f}%)")

        # Informações da chave mestra
        print("\n🔑 Informações da chave mestra...")
        key_exists = manager.key_manager.key_exists()
        print(f"Arquivo de chave existe: {'✅ Sim' if key_exists else '❌ Não'}")
        if key_exists:
            file_size = manager.key_manager.key_file.stat().st_size
            print(f"Tamanho do arquivo: {file_size} bytes")
            print(f"Caminho: {manager.key_manager.key_file}")

        print("\n🎉 Exemplo concluído com sucesso!")
        print("\n💡 Dicas importantes:")
        print("   • O arquivo 'key.key' contém sua chave mestra - mantenha-o seguro!")
        print("   • Faça backup regular do arquivo key.key")
        print("   • Se perder o arquivo key.key, todas as senhas ficarão inacessíveis")
        print("   • Use o menu 'Gerenciar Chave Mestra' para criar backups")

    except Exception as e:
        print(f"❌ Erro durante o exemplo: {e}")


if __name__ == "__main__":
    exemplo_uso()
