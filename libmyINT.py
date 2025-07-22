#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import requests
import json
import socket
import whois
import dns.resolver
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import Fore, Style, init

# Инициализация colorama
init(autoreset=True)

# Константы
VERSION = "1.1"
AUTHOR = "Anonymous Researcher"
GITHUB = "https://github.com/yourusername/libmyINT"
BANNER = f"""
{Fore.RED} _     _ _     _       ___ _____ _____ 
{Fore.RED}| |   (_) |   | |     |_  |_   _|_   _|
{Fore.RED}| |    _| |__ | |__     | | | |   | |  
{Fore.RED}| |   | | '_ \| '_ \    | | | |   | |  
{Fore.RED}| |___| | |_) | | | |/\__/ /_| |_ _| |_ 
{Fore.RED}\_____/_|_.__/|_| |_|\____/ \___/ \___/ 
{Fore.YELLOW}Version: {VERSION} | By: {AUTHOR}
{Fore.CYAN}GitHub: {GITHUB}
{Style.RESET_ALL}
"""

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_slow(text):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.03)
    print()

def main_menu():
    clear_screen()
    print(BANNER)
    print(f"{Fore.GREEN}Основное меню:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Поиск информации по IP")
    print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Поиск информации по домену")
    print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Поиск информации по номеру телефона")
    print(f"{Fore.YELLOW}4.{Style.RESET_ALL} Поиск информации по email")
    print(f"{Fore.YELLOW}5.{Style.RESET_ALL} Поиск информации по имени пользователя")
    print(f"{Fore.YELLOW}6.{Style.RESET_ALL} Проверка утечек данных (Scylla.sh)")
    print(f"{Fore.YELLOW}7.{Style.RESET_ALL} Выход")
    
    choice = input(f"\n{Fore.CYAN}Выберите опцию (1-7): {Style.RESET_ALL}")
    return choice

def ip_lookup():
    clear_screen()
    print(f"{Fore.GREEN}Поиск информации по IP{Style.RESET_ALL}\n")
    ip = input(f"{Fore.CYAN}Введите IP-адрес: {Style.RESET_ALL}")
    
    try:
        # Проверка валидности IP
        socket.inet_aton(ip)
        
        print(f"\n{Fore.YELLOW}[*] Запрос информации об IP {ip}...{Style.RESET_ALL}")
        
        # Использование ip-api.com
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
        data = response.json()
        
        if data['status'] == 'success':
            print(f"\n{Fore.GREEN}=== Основная информация ==={Style.RESET_ALL}")
            print(f"Страна: {data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})")
            print(f"Регион: {data.get('regionName', 'N/A')} ({data.get('region', 'N/A')})")
            print(f"Город: {data.get('city', 'N/A')}")
            print(f"Район: {data.get('district', 'N/A')}")
            print(f"Почтовый индекс: {data.get('zip', 'N/A')}")
            print(f"Часовой пояс: {data.get('timezone', 'N/A')}")
            print(f"Координаты: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
            
            print(f"\n{Fore.GREEN}=== Сетевая информация ==={Style.RESET_ALL}")
            print(f"Провайдер: {data.get('isp', 'N/A')}")
            print(f"Организация: {data.get('org', 'N/A')}")
            print(f"AS номер: {data.get('as', 'N/A')}")
            print(f"AS имя: {data.get('asname', 'N/A')}")
            print(f"Обратный DNS: {data.get('reverse', 'N/A')}")
            
            print(f"\n{Fore.GREEN}=== Техническая информация ==={Style.RESET_ALL}")
            print(f"Мобильное соединение: {'Да' if data.get('mobile', False) else 'Нет'}")
            print(f"Прокси/VPN: {'Да' if data.get('proxy', False) else 'Нет'}")
            print(f"Хостинг: {'Да' if data.get('hosting', False) else 'Нет'}")
        else:
            print(f"{Fore.RED}Ошибка: {data.get('message', 'Неизвестная ошибка')}{Style.RESET_ALL}")
    
    except socket.error:
        print(f"{Fore.RED}Ошибка: Неверный IP-адрес{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def domain_lookup():
    clear_screen()
    print(f"{Fore.GREEN}Поиск информации по домену{Style.RESET_ALL}\n")
    domain = input(f"{Fore.CYAN}Введите доменное имя (например: example.com): {Style.RESET_ALL}")
    
    try:
        print(f"\n{Fore.YELLOW}[*] Запрос WHOIS информации...{Style.RESET_ALL}")
        domain_info = whois.whois(domain)
        
        print(f"\n{Fore.GREEN}=== Регистрационная информация ==={Style.RESET_ALL}")
        print(f"Домен: {domain_info.domain_name}")
        print(f"Регистратор: {domain_info.registrar}")
        print(f"Дата создания: {domain_info.creation_date}")
        print(f"Дата истечения: {domain_info.expiration_date}")
        print(f"Дата последнего обновления: {domain_info.updated_date}")
        print(f"Статус: {', '.join(domain_info.status) if domain_info.status else 'N/A'}")
        
        print(f"\n{Fore.GREEN}=== Контактная информация ==={Style.RESET_ALL}")
        print(f"Владелец: {domain_info.name}")
        print(f"Организация: {domain_info.org}")
        print(f"Адрес: {domain_info.address}")
        print(f"Город: {domain_info.city}")
        print(f"Страна: {domain_info.country}")
        print(f"Почтовый индекс: {domain_info.zipcode}")
        
        print(f"\n{Fore.YELLOW}[*] Запрос DNS информации...{Style.RESET_ALL}")
        print(f"\n{Fore.GREEN}=== DNS записи ==={Style.RESET_ALL}")
        
        try:
            # A записи
            a_records = dns.resolver.resolve(domain, 'A')
            print("A записи:")
            for a in a_records:
                print(f" - {a.address}")
        except:
            print("A записи: не найдены")
            
        try:
            # MX записи
            mx_records = dns.resolver.resolve(domain, 'MX')
            print("\nMX записи:")
            for mx in mx_records:
                print(f" - {mx.exchange} (приоритет {mx.preference})")
        except:
            print("\nMX записи: не найдены")
            
        try:
            # NS записи
            ns_records = dns.resolver.resolve(domain, 'NS')
            print("\nNS записи:")
            for ns in ns_records:
                print(f" - {ns.target}")
        except:
            print("\nNS записи: не найдены")
            
        try:
            # TXT записи
            txt_records = dns.resolver.resolve(domain, 'TXT')
            print("\nTXT записи:")
            for txt in txt_records:
                print(f" - {txt.strings}")
        except:
            print("\nTXT записи: не найдены")
            
    except Exception as e:
        print(f"{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def phone_lookup():
    clear_screen()
    print(f"{Fore.GREEN}Поиск информации по номеру телефона{Style.RESET_ALL}\n")
    phone = input(f"{Fore.CYAN}Введите номер телефона (с кодом страны, например +79123456789): {Style.RESET_ALL}")
    
    try:
        print(f"\n{Fore.YELLOW}[*] Анализ номера с помощью phonenumbers...{Style.RESET_ALL}")
        
        # Парсинг номера
        parsed_number = phonenumbers.parse(phone)
        
        if not phonenumbers.is_valid_number(parsed_number):
            print(f"{Fore.RED}Ошибка: Номер недействителен{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.GREEN}=== Основная информация ==={Style.RESET_ALL}")
        print(f"Международный формат: {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
        print(f"E.164 формат: {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)}")
        print(f"Национальный формат: {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)}")
        
        # Информация о операторе
        print(f"\n{Fore.GREEN}=== Информация об операторе ==={Style.RESET_ALL}")
        try:
            operator = carrier.name_for_number(parsed_number, "ru")
            print(f"Оператор: {operator if operator else 'Неизвестно'}")
        except:
            print("Оператор: Информация недоступна")
        
        # Геолокация
        print(f"\n{Fore.GREEN}=== Геолокация ==={Style.RESET_ALL}")
        try:
            region = geocoder.description_for_number(parsed_number, "ru")
            print(f"Регион: {region if region else 'Неизвестно'}")
        except:
            print("Регион: Информация недоступна")
        
        # Часовой пояс
        print(f"\n{Fore.GREEN}=== Часовой пояс ==={Style.RESET_ALL}")
        try:
            tz = timezone.time_zones_for_number(parsed_number)
            print(f"Часовой пояс: {tz[0] if tz else 'Неизвестно'}")
        except:
            print("Часовой пояс: Информация недоступна")
            
        # Дополнительные проверки
        print(f"\n{Fore.GREEN}=== Дополнительная информация ==={Style.RESET_ALL}")
        print(f"Тип номера: {phonenumbers.number_type(parsed_number)}")
        print(f"Возможный номер: {'Да' if phonenumbers.is_possible_number(parsed_number) else 'Нет'}")
        print(f"Действительный номер: {'Да' if phonenumbers.is_valid_number(parsed_number) else 'Нет'}")
        
    except Exception as e:
        print(f"{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def email_lookup():
    clear_screen()
    print(f"{Fore.GREEN}Поиск информации по email{Style.RESET_ALL}\n")
    email = input(f"{Fore.CYAN}Введите email адрес: {Style.RESET_ALL}")
    
    try:
        print(f"\n{Fore.YELLOW}[*] Проверка email через MailboxValidator API...{Style.RESET_ALL}")
        
        # Бесплатный вариант проверки email (без API ключа)
        domain = email.split('@')[-1]
        
        print(f"\n{Fore.GREEN}=== Основная информация ==={Style.RESET_ALL}")
        print(f"Email: {email}")
        print(f"Домен: {domain}")
        
        # Проверка MX записей
        print(f"\n{Fore.YELLOW}[*] Проверка MX записей домена...{Style.RESET_ALL}")
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            print(f"{Fore.GREEN}MX записи найдены:{Style.RESET_ALL}")
            for mx in mx_records:
                print(f" - {mx.exchange} (приоритет {mx.preference})")
        except:
            print(f"{Fore.RED}MX записи не найдены - домен может не существовать{Style.RESET_ALL}")
        
        # Проверка через MailboxValidator (бесплатный вариант)
        print(f"\n{Fore.YELLOW}[*] Проверка через MailboxValidator...{Style.RESET_ALL}")
        try:
            response = requests.get(f"https://api.mailboxvalidator.com/v1/validation/single?email={email}&key=free")
            data = response.json()
            
            if data.get('status') == 'True':
                print(f"\n{Fore.GREEN}=== Результаты проверки ==={Style.RESET_ALL}")
                print(f"Действительный email: {'Да' if data.get('is_verified') == 'True' else 'Нет'}")
                print(f"Домен: {data.get('domain', 'N/A')}")
                print(f"Почтовый сервер: {data.get('mail_server', 'N/A')}")
                print(f"SMTP проверка: {'Да' if data.get('smtp_connect') == 'True' else 'Нет'}")
                print(f"Валидный синтаксис: {'Да' if data.get('is_valid_syntax') == 'True' else 'Нет'}")
                print(f"Домен существует: {'Да' if data.get('is_domain') == 'True' else 'Нет'}")
            else:
                print(f"{Fore.RED}Ошибка проверки: {data.get('error_message', 'Неизвестная ошибка')}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Ошибка API: {str(e)}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def username_lookup():
    clear_screen()
    print(f"{Fore.GREEN}Поиск информации по имени пользователя{Style.RESET_ALL}\n")
    username = input(f"{Fore.CYAN}Введите имя пользователя: {Style.RESET_ALL}")
    
    try:
        print(f"\n{Fore.YELLOW}[*] Поиск по социальным сетям...{Style.RESET_ALL}")
        
        # Список социальных сетей для проверки
        social_networks = {
            "GitHub": f"https://github.com/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "Facebook": f"https://facebook.com/{username}",
            "LinkedIn": f"https://linkedin.com/in/{username}",
            "Reddit": f"https://reddit.com/user/{username}",
            "YouTube": f"https://youtube.com/@{username}",
            "TikTok": f"https://tiktok.com/@{username}",
            "Telegram": f"https://t.me/{username}",
            "VK": f"https://vk.com/{username}",
            "Pinterest": f"https://pinterest.com/{username}",
            "Twitch": f"https://twitch.tv/{username}",
            "Medium": f"https://medium.com/@{username}"
        }
        
        print(f"\n{Fore.GREEN}=== Результаты поиска ==={Style.RESET_ALL}")
        
        for name, url in social_networks.items():
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[+] {name}: {url}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] {name}: Не найдено{Style.RESET_ALL}")
            except:
                print(f"{Fore.RED}[-] {name}: Ошибка проверки{Style.RESET_ALL}")
                
    except Exception as e:
        print(f"{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def check_leaks():
    clear_screen()
    print(f"{Fore.GREEN}Проверка утечек данных (Scylla.sh){Style.RESET_ALL}\n")
    query = input(f"{Fore.CYAN}Введите email/имя пользователя/номер телефона: {Style.RESET_ALL}")
    
    try:
        print(f"\n{Fore.YELLOW}[*] Проверка через Scylla.sh API...{Style.RESET_ALL}")
        
        # Использование Scylla.sh (открытая база утечек)
        response = requests.get(f"https://scylla.sh/search?q={query}", headers={'User-Agent': 'libmyINT OSINT Tool'})
        
        if response.status_code == 200:
            data = response.json()
            
            if len(data) > 0:
                print(f"\n{Fore.RED}=== Обнаружены утечки ==={Style.RESET_ALL}")
                for leak in data:
                    print(f"\n{Fore.YELLOW}Источник: {leak.get('fields', {}).get('domain', 'N/A')}{Style.RESET_ALL}")
                    print(f"Дата утечки: {leak.get('_source', {}).get('seen_date', 'N/A')}")
                    print(f"Тип данных: {leak.get('_source', {}).get('data_type', 'N/A')}")
                    
                    # Выводим все доступные поля
                    print(f"\n{Fore.CYAN}Доступные данные:{Style.RESET_ALL}")
                    for key, value in leak.get('fields', {}).items():
                        if key not in ['_id', '_index'] and value:
                            print(f"{key}: {value}")
            else:
                print(f"\n{Fore.GREEN}[+] Данные не найдены в известных утечках{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Ошибка API: {response.status_code}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def main():
    while True:
        choice = main_menu()
        
        if choice == '1':
            ip_lookup()
        elif choice == '2':
            domain_lookup()
        elif choice == '3':
            phone_lookup()
        elif choice == '4':
            email_lookup()
        elif choice == '5':
            username_lookup()
        elif choice == '6':
            check_leaks()
        elif choice == '7':
            clear_screen()
            print_slow(f"{Fore.GREEN}Спасибо за использование libmyINT!{Style.RESET_ALL}")
            print_slow(f"{Fore.YELLOW}Выход...{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"\n{Fore.RED}Неверный выбор. Пожалуйста, выберите от 1 до 7.{Style.RESET_ALL}")
            time.sleep(2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Программа прервана пользователем.{Style.RESET_ALL}")
        sys.exit(0)