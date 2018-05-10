# coding=utf-8
#####################################################
#                    Versao 4.3                     #
#                                                   #
#                 Data 09-01-2018                  #
#                                                   #
#            Autor: Leonardo Monteiro               #
#      E-mail: decastromonteiro@gmail.com           #
#                                                   #
#####################################################
try:
    # noinspection PyUnresolvedReferences
    import bigsuds
except ImportError:
    print("Instale a biblioteca bigsuds utilizando pip, e. pip install bigsuds.")
    input()

import getpass
import json
import datetime
import re
from collections import namedtuple
import os
import argparse

# Patterns to Search for DNS Domains, DNS Zones, and to convert a LIST String to a concatenation of elements
domain_pattern = ".+?(?=\.epc)|.+?(?=\.mnc)"
zone_pattern = "\mnc.+|epc.+"
list_to_string_pattern = r"\'|\,|\[|\]|"
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help="IP Address of F5 BIG-IP Platform", type=str)
parser.add_argument("-u", "--user", help="Username to access F5 BIG-IP Platform", type=str)
parser.add_argument("-p", "--password", help="Password to access F5 BIG-IP Platform", type=str)
parser.add_argument("-a", "--action",
                    help="Choose the action to be performed by CVNA APP F5."
                         "1: Consultar zona no DNS\n"
                         "2: Criar/Remover Entradas no DNS\n"
                         "3: Sair", type=str)
parser.add_argument("-v", "--view", help="Choose the DNS view to use", type=str)
parser.add_argument("-f", "--file", help="Input file path containing configurations", type=str)
parser.add_argument("-z", "--zone",
                    help="Choose the DNS zone to query.\n This option is used only when --action is 1.", type=str)
parser.add_argument("-n", "--name", help="Input name to query.\n This option is used only when --action is 1.",
                    type=str)
parser.add_argument("-e", "--export",
                    help="Choose whether to export the query to a file or not.\ns: export\n\nn: no export\n"
                         "\nThis option is used only when --action is 1.",
                    type=str)
args = parser.parse_args()


def flush_dns_configuration(b, view_name, naptr_records, naptr_records_delete, a_records, a_records_delete):
    """This function is used to flush all Records configuration to the BIG-IP ZoneRunner App.

       The objects inside naptr_records / naptr_records_delete looks like this:

        {"service": "x-3gpp-mme:x-gn:x-s10",
        "domain_name": "tac-lb25.tac-hb8E.tac.epc.mnc004.mcc724.3gppnetwork.org.",
        "flags": "a", "preference": 10,
        "ttl": 300, "regexp": "\"\"", "order": 10,
        "replacement": "topoff.vip-gn.DMBSA1.node.epc.mnc004.mcc724.3gppnetwork.org."},

        {"service": "x-3gpp-mme:x-gn:x-s10",
        "domain_name": "tac-lb25.tac-hb8E.tac.epc.mnc004.mcc724.3gppnetwork.org.",
        "flags": "a", "preference": 10, "ttl": 300, "regexp": "\"\"", "order": 10,
        "replacement": "topoff.vip-gn.DMCTA1.node.epc.mnc004.mcc724.3gppnetwork.org."},

        {"service": "x-3gpp-sgw:x-s11:x-s5-gtp",
        "domain_name": "tac-lb1A.tac-hb7A.tac.epc.mnc004.mcc724.3gppnetwork.org.",
        "flags": "a", "preference": 10, "ttl": 300, "regexp": "\"\"", "order": 10,
        "replacement": "topoff.vip-s11.GPCTA1.node.epc.mnc004.mcc724.3gppnetwork.org."}

        The objects inside a_records / a_records_delete looks like this:

        {"domain_name":"testp.tim.br.mnc003.mcc724.gprs.", "ip_address": "10.221.58.214", "ttl":300}
        {"domain_name":"testp.tim.br.mnc004.mcc724.gprs.", "ip_address": "10.221.58.214", "ttl":300}
        {"domain_name":"testp.tim.br.mnc002.mcc724.gprs.", "ip_address": "10.221.58.214", "ttl":300}

       For more information go to devcentral.f5.com and search for iControl API.
    """

    def gather_evidence():
        """
        This function is used to gather the evidence of entries configured through the main function.
        It returns a list of entries gathered.


        """
        group_of_domains = []
        group_of_domains_to_remove = []

        if a_records:
            for i in xrange(len(a_records)):
                domain = re.search(domain_pattern, [dicts.get("domain_name") for dicts in a_records][i])
                group_of_domains.append(domain.group())

        if naptr_records:
            for i in xrange(len(naptr_records)):
                domain = re.search(domain_pattern,
                                   [dicts.get("domain_name") for dicts in naptr_records][i])
                group_of_domains.append(domain.group())

        group_of_domains = set(group_of_domains)

        if a_records_delete:
            for i in xrange(len(a_records_delete)):
                domain = re.search(domain_pattern,
                                   [dicts.get("domain_name") for dicts in a_records_delete][i])
                group_of_domains_to_remove.append(domain.group())

        if naptr_records_delete:
            for i in xrange(len(naptr_records_delete)):
                domain = re.search(domain_pattern,
                                   [dicts.get("domain_name") for dicts in naptr_records_delete][i])
                group_of_domains_to_remove.append(domain.group())
        group_of_domains_to_remove = set(group_of_domains_to_remove)

        evidences_list = list()

        if group_of_domains:
            evidences_list.append("\nVerificacao das entradas configuradas:\n")
            print("\nVerificacao das entradas configuradas:\n")

            for domain in group_of_domains:
                new_entries, full_path = gather_dns_records(b, regex=domain, view_name=view_name, zone_name="",
                                                            export="")
                if new_entries:
                    evidences_list.append("\nSeguem as entradas configuradas com domain '{}':\n".format(domain))
                    print("\nSeguem as entradas configuradas com domain '{}':\n".format(domain))
                    for entries in new_entries:
                        print(entries + '\n')
                        evidences_list.append(entries)
                else:
                    evidences_list.append("Nao existem entradas com domain '{}'".format(domain))
                    print("Nao existem entradas com domain '{}'".format(domain))

        if group_of_domains_to_remove:
            evidences_list.append("\nVerificacao das entradas removidas:\n")
            print("\nVerificacao das entradas removidas:\n")

            for domain in group_of_domains_to_remove:
                new_entries, full_path = gather_dns_records(b, regex=domain, view_name=view_name, zone_name="",
                                                            export="")

                if new_entries:
                    evidences_list.append("\nSeguem as entradas configuradas com domain '{}':\n".format(domain))
                    print("\nSeguem as entradas configuradas com domain '{}':\n".format(domain))
                    for entries in new_entries:
                        print(entries + '\n')
                        evidences_list.append(entries)
                else:
                    evidences_list.append("Nao existem entradas com domain '{}'".format(domain))
                    print("Nao existem entradas com domain '{}'".format(domain))
        return evidences_list

    BadRecord = namedtuple('BadRecord', 'Record Error')
    TypeofSuccess = namedtuple('TypeofSuccess', 'Flag Evidence BadRecords')
    badrecord_list = list()
    total_len = len(a_records) + len(a_records_delete) + len(naptr_records) + len(naptr_records_delete)
    # Add NAPTR Records

    if len(naptr_records) != 0:
        records_to_remove = list()
        for records in naptr_records:
            try:
                b.Management.ResourceRecord.add_naptr(
                    view_zones=[{"view_name": view_name, "zone_name": re.search(zone_pattern, records.get(
                        "domain_name")).group()}],
                    naptr_records=[[records]],
                )
            except Exception as error:
                badrecord_list.append(BadRecord(Record=records, Error=error))
                records_to_remove.append(records)
                continue
        for records in records_to_remove:
            naptr_records.remove(records)
    # Delete NAPTR Records

    if len(naptr_records_delete) != 0:
        records_to_remove = list()
        for records in naptr_records_delete:
            try:
                b.Management.ResourceRecord.delete_naptr(
                    view_zones=[{"view_name": view_name, "zone_name": re.search(zone_pattern, records.get(
                        "domain_name")).group()}],
                    naptr_records=[[records]],
                )
            except Exception as error:
                badrecord_list.append(BadRecord(Record=records, Error=error))
                records_to_remove.append(records)
                continue
        for records in records_to_remove:
            naptr_records_delete.remove(records)
    # Add A Records

    if len(a_records) != 0:
        records_to_remove = list()
        for records in a_records:
            try:
                b.Management.ResourceRecord.add_a(
                    view_zones=[{"view_name": view_name, "zone_name": re.search(zone_pattern, records.get(
                        "domain_name")).group()}],
                    a_records=[[records]],
                    sync_ptrs=["false"]
                )
            except Exception as error:
                badrecord_list.append(BadRecord(Record=records, Error=error))
                records_to_remove.append(records)
                continue
        for records in records_to_remove:
            a_records.remove(records)
    # Delete A Records

    if len(a_records_delete) != 0:
        records_to_remove = list()
        for records in a_records_delete:
            try:
                b.Management.ResourceRecord.delete_a(
                    view_zones=[{"view_name": view_name, "zone_name": re.search(zone_pattern, records.get(
                        "domain_name")).group()}],
                    a_records=[[records]],
                    sync_ptrs=["false"]
                )
            except Exception as error:
                badrecord_list.append(BadRecord(Record=records, Error=error))
                records_to_remove.append(records)
                continue
        for records in records_to_remove:
            a_records_delete.remove(records)

    if len(badrecord_list) == total_len:
        return TypeofSuccess(Flag="A", Evidence=None, BadRecords=badrecord_list)
    elif badrecord_list:
        evidence_list = gather_evidence()
        return TypeofSuccess(Flag="S", Evidence=evidence_list, BadRecords=badrecord_list)
    else:
        evidence_list = gather_evidence()
        return TypeofSuccess(Flag="N", Evidence=evidence_list, BadRecords=None)


def gather_dns_records(b, regex, view_name, zone_name, export):
    """This functions is used to query the ZoneRunner App database.
       Returnts a list of entries and the full_path of the export file.
    """
    if not view_name.strip():
        view_name = "internal"
    now = datetime.datetime.now()
    date = '{}-{}-{}_{}-{}-{}'.format(now.day, now.month, now.year, now.hour, now.minute, now.second)
    records_data = []
    current_dir = os.getcwd()
    file_name = view_name + "_{}_{}.txt".format(zone_name, date)
    full_path = os.path.join(current_dir, file_name)
    for rrs in b.Management.ResourceRecord.get_rrs(
            view_zones=[{"view_name": view_name, "zone_name": zone_name  # example: "mnc002.mcc724.3gppnetwork.org."
                         }]):
        if regex.strip() == "":
            if export.lower() == "s":
                with open(full_path, "wb") as f:
                    for records in rrs:
                        f.write(records + "\n")
                        records_data.append(records)
            else:
                for records in rrs:
                    records_data.append(records)
        else:
            if export.lower() == "s":
                with open(full_path, "wb") as f:
                    for records in rrs:
                        if regex.lower() in records or regex.upper() in records or regex in records:
                            f.write(records + "\n")
                            records_data.append(records)
            else:
                for records in rrs:
                    if regex.lower() in records or regex.upper() in records or regex in records:
                        records_data.append(records)
    return records_data, full_path


def evolved_extract_records(arquivo_input):
    """This function is used to extract all Records from a file to their respective lists.

       The objects inside the file looks like this:

        {"action": "add", service": "x-3gpp-mme:x-gn:x-s10",
        "domain_name": "tac-lb25.tac-hb8E.tac.epc.mnc004.mcc724.3gppnetwork.org.",
        "flags": "a", "preference": 10,
        "ttl": 300, "regexp": "\"\"", "order": 10,
        "replacement": "topoff.vip-gn.DMBSA1.node.epc.mnc004.mcc724.3gppnetwork.org."},
        {"action": "add", "service": "x-3gpp-mme:x-gn:x-s10",
        "domain_name": "tac-lb25.tac-hb8E.tac.epc.mnc004.mcc724.3gppnetwork.org.",
        "flags": "a", "preference": 10, "ttl": 300, "regexp": "\"\"", "order": 10,
        "replacement": "topoff.vip-gn.DMCTA1.node.epc.mnc004.mcc724.3gppnetwork.org."},
        {"action": "remove", "service": "x-3gpp-sgw:x-s11:x-s5-gtp",
        "domain_name": "tac-lb1A.tac-hb7A.tac.epc.mnc004.mcc724.3gppnetwork.org.",
        "flags": "a", "preference": 10, "ttl": 300, "regexp": "\"\"", "order": 10,
        "replacement": "topoff.vip-s11.GPCTA1.node.epc.mnc004.mcc724.3gppnetwork.org."}
        {"action": "add", "domain_name":"testp.tim.br.mnc003.mcc724.gprs.", "ip_address": "10.221.58.214", "ttl":300}
        {"action": "add", "domain_name":"testp.tim.br.mnc004.mcc724.gprs.", "ip_address": "10.221.58.214", "ttl":300}
        {"action": "remove", "domain_name":"testp.tim.br.mnc002.mcc724.gprs.", "ip_address": "10.221.58.214", "ttl":300}

       For more information go to devcentral.f5.com and search for iControl API.
    """
    RecordCollection = namedtuple('Records',
                                  'a_records a_records_delete naptr_records naptr_records_delete bad_entries')
    BadEntries = namedtuple('BadEntries', 'File Line Entry Flag')
    result = RecordCollection(a_records=[], a_records_delete=[], naptr_records=[], naptr_records_delete=[],
                              bad_entries=[])
    line_counter = 0
    for arquivo in arquivo_input:
        with open(arquivo, "r") as resrec:
            for lines in resrec:
                line_counter += 1
                if lines.strip():
                    lines = json.loads(lines)
                    try:
                        if lines.get("replacement"):
                            if lines.get("action").lower() == "add":
                                lines.pop("action")
                                result.naptr_records.append(lines)
                            elif lines.get("action").lower() == "remove":
                                lines.pop("action")
                                result.naptr_records_delete.append(lines)
                            else:
                                result.bad_entries.append(BadEntries(File=arquivo, Line=line_counter, Entry=lines,
                                                                     Flag="Parametro action fora do padrao."))
                        else:
                            if lines.get("action").lower() == "add":
                                lines.pop("action")
                                result.a_records.append(lines)
                            elif lines.get("action").lower() == "remove":
                                lines.pop("action")
                                result.a_records_delete.append(lines)
                            else:
                                result.bad_entries.append(BadEntries(File=arquivo, Line=line_counter, Entry=lines,
                                                                     Flag="Parametro action fora do padrao."))
                    except AttributeError:
                        result.bad_entries.append(BadEntries(File=arquivo, Line=line_counter, Entry=lines,
                                                             Flag="Parametro action nao existente."))
                        continue
    return result


def main_cvna_f5_app_main():
    print("\nBem vindo a ferramenta de CVNA do BIG-IP F5\n")
    _status = "NOK"
    while _status != "OK":
        if not args.ip or not args.user or not args.password:
            print("Por favor, insira as infos abaixo para obter acesso ao BIG-IP:\n")

        hostname = args.ip if args.ip else raw_input("Digite o IP do Big-IP: ")
        username = args.user if args.user else raw_input("Usuario: ")
        password = args.password if args.password else getpass.getpass('Senha: ')
        print('Tentanto conexao com o BIG-IP F5...')
        b = bigsuds.BIGIP(

            hostname=hostname.strip(),
            username=username.strip(),
            password=password.strip()
        )

        # Teste de Conectividade/Autorizacao
        try:
            version = b.System.Inet.get_version()
            system_name = b.System.Inet.get_hostname()
            print("\nConectado ao BIG-IP: {}\nVersao: {}\n\n".format(system_name, version))
            _status = "OK"
            args.password = None
        except bigsuds.ConnectionError as error:
            if "HTTP Error 401:" in error.message:
                args.user = None
                args.password = None
                print("\n\nUsuario ou Senha errados, por favor verifique e tente novamente."
                      "\n\nPressione <Enter> para sair.")
                raw_input()
            else:
                # noinspection PyProtectedMember
                args.ip = None
                print("\n\nUma tentativa de conexao com o BIG-IP: [{}] falhou. Verifique o IP e tente novamente."
                      "\n\nPressione <Enter> para sair.".format(b._hostname))
                raw_input()
        except Exception as error:
            args.ip = None
            args.user = None
            args.password = None
            print("Encontramos um erro. Reporte-o ao desenvolvedor (decastromonteiro@gmail.com).")
            print("\n\n" + error.message)
            raw_input()

    while True:
        if not args.action:
            print("\nEscolha uma das opcoes abaixo para prosseguir:")
            print("1: Consultar zona no DNS\n"
                  "2: Criar/Remover Entradas no DNS\n"
                  "3: Sair\n"
                  )

            choose_action = raw_input("> ")
        else:
            choose_action = args.action.strip()

        if choose_action == "1":
            view_name = args.view.strip() if args.view else raw_input(
                "Digite o nome da view que deseja consultar: ").strip()
            zone_name = args.zone.strip() if args.zone else raw_input(
                "Digite o nome da zona que deseja consultar: ").strip()
            regex = args.name.strip() if args.name else raw_input(
                "Digite um nome especifico que deseja consultar dentro da zona: ").strip()
            export = args.export.strip() if args.export else raw_input(
                "Deseja exportar as respostas para um arquivo? (s\\n): ").strip()
            if export.lower() == "s":
                print("Consultando o DNS...")
                try:
                    result, full_path = gather_dns_records(b, regex, view_name, zone_name, export)
                    print("Foi gerado o arquivo {} na seguinte pasta: {}".format(os.path.split(full_path)[1],
                                                                                 os.path.split(full_path)[0]))
                except Exception as err:
                    print("Encontramos um erro. Reporte-o ao desenvolvedor (decastromonteiro@gmail.com).")
                    print(err)
                    raw_input()
            else:
                print("Seguem as entradas recuperadas:\n")
                print("\n")
                try:
                    result, full_path = gather_dns_records(b, regex, view_name, zone_name, export)
                    for r in result:
                        print(r + '\n')
                except Exception as err:
                    print("Encontramos um erro. Reporte-o ao desenvolvedor (decastromonteiro@gmail.com).")
                    print(err)
                    raw_input()

        elif choose_action == "2":

            view_name = args.view.strip() if args.view else raw_input("Escreva o nome da view que deseja configurar: ")
            arquivo_input = args.file.strip() if args.file else raw_input(
                "Escreva os nomes dos arquivos de input, utilizando ponto e virgula (;) "
                "como separador: ").split(";")
            try:

                records = evolved_extract_records(arquivo_input)
                now = datetime.datetime.now()
                date = '{}-{}-{}_{}-{}-{}'.format(now.day, now.month, now.year, now.hour, now.minute, now.second)

                if records.bad_entries:
                    current_dir = os.getcwd()
                    badentries_log = "log_BadEntries_{}.log".format(date)
                    full_path = os.path.join(current_dir, badentries_log)
                    print("Existem entradas fora do padrao estabelecido. Verifique o arquivo {}.".format(
                        full_path))
                    with open(full_path, 'wb') as f:
                        f.write("\nEntradas fora do padrao:\n\n")
                        for entry in records.bad_entries:
                            f.write("Arquivo: {}\nLinha: {}\nEntrada: {}\nFlag: {}\n\n############\n\n".format(
                                entry.File, entry.Line, entry.Entry, entry.Flag
                            ))
                elif (not records.a_records and not records.naptr_records) and \
                        (not records.a_records_delete and not records.naptr_records_delete):

                    print("Nao foi possivel extrair nenhuma configuracao dos arquivos: {}".format(
                        arquivo_input
                    ))
                    print("Verifique o conteudo dos arquivos e tente novamente.")
                    continue
                result = flush_dns_configuration(b, view_name, records.naptr_records,
                                                 records.naptr_records_delete, records.a_records,
                                                 records.a_records_delete)
                arquivo_input_final = list()
                for arquivo in arquivo_input:
                    arquivo_final = os.path.split(arquivo)[1]
                    arquivo_input_final.append(arquivo_final)
                current_dir = os.getcwd()
                file_name = "log_{}_{}.log".format(date,
                                                   re.sub(list_to_string_pattern, "", str(arquivo_input_final)).
                                                   replace(" ", "_")
                                                   )
                full_path = os.path.join(current_dir, file_name)
                if result.Flag == "A":
                    print("\nOcorreram erros em todas as entradas, portanto nenhuma foi configurada. "
                          "Verifique o log {}.".format(file_name))
                    with open(full_path, 'wb') as f:
                        f.write("Data: {}/{}/{}\nHora: {}:{}:{}\nUsuario: {}\nArquivos Utilizados: {}\n"
                                "Flag: {}\n\n".format(now.day, now.month, now.year, now.hour, now.minute,
                                                      now.second, username, arquivo_input,
                                                      "Erro em todas as entradas.")
                                )
                        if result.BadRecords:
                            for entry in result.BadRecords:
                                f.write("Entrada: {}\nErro: {}\n\n".format(entry.Record, entry.Error))
                        else:
                            # noinspection PyUnboundLocalVariable
                            # If there is no BadRecords, it means all were BadEntries
                            f.write("Todas as entradas estavam fora do padrao. "
                                    "Verifique o arquivo {}.".format(badentries_log))
                elif result.Flag == "S":
                    print("\nOcorreram erros em algumas entradas, favor verificar no log {}.".format(file_name))
                    with open(full_path, 'wb') as f:
                        f.write("Data: {}/{}/{}\nHora: {}:{}:{}\nUsuario: {}\nArquivos Utilizados: {}\n"
                                "Flag: {}\n\n".format(now.day, now.month, now.year, now.hour,
                                                      now.minute, now.second, username, arquivo_input,
                                                      "Erro em algumas entradas.")
                                )
                        f.write("Entradas nao configuradas, por erros:\n\n")
                        for entry in result.BadRecords:
                            f.write("Entrada: {}\nErro: {}\n\n".format(entry.Record, entry.Error))
                        for entry in result.Evidence:
                            f.write(entry + '\n')
                elif result.Flag == "N":
                    print("\nConfiguracoes concluidas com sucesso!\n")
                    with open(full_path, 'wb') as f:
                        f.write("Data: {}/{}/{}\nHora: {}:{}:{}\nUsuario: {}\nArquivos Utilizados: {}\n"
                                "Flag: {}\n\n".format(now.day, now.month, now.year, now.hour,
                                                      now.minute, now.second, username, arquivo_input,
                                                      "Todas as entradas foram configuradas.")
                                )
                        for evidence in result.Evidence:
                            f.write(evidence + '\n')

                    print("\nFoi gerado o log {}.\n".format(file_name))
                else:
                    pass
            except Exception as err:
                print("Encontramos um erro. Reporte-o ao desenvolvedor (decastromonteiro@gmail.com).")
                print(err)
                raw_input()

        elif choose_action == "3":
            print("Obrigado por utilizar a ferramenta de CVNA do BIG-IP F5!")
            raw_input()
            break

        args.action = None
        args.view = None
        args.zone = None
        args.name = None
        args.export = None
        args.file = None


if __name__ == "__main__":
    main_cvna_f5_app_main()
