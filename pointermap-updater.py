import json
import pefile
import logging

# Настройка логирования
logging.basicConfig(
    filename="string_analysis.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    encoding="utf-8"
)

# 🔧 Настройки
missing_log_path = "missing_strings.log"
mismatch_json_path = "mismatch_occurrences.json"
include_mismatches_in_main_output = False  # ← переключатель

used_vas = set()

def load_original_entries(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)

def get_va_from_offset(pe, offset):
    for section in pe.sections:
        start = section.PointerToRawData
        end = start + section.SizeOfRawData
        if start <= offset < end:
            delta = offset - start
            return pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + delta
    return None

def va_to_le_bytes(va):
    if va is None:
        return None
    return va.to_bytes(8, byteorder='little')

def find_exact_string(data, target):
    if not target:
        return []
    b = target.encode()
    results = []
    start = 0
    while True:
        offset = data.find(b, start)
        if offset == -1:
            break
        before = data[offset - 1] if offset > 0 else None
        after = data[offset + len(b)] if offset + len(b) < len(data) else None
        if before == 0 and after == 0:
            results.append(offset)
        start = offset + 1
    return results

def is_va_unique(va):
    if va is None:
        return False
    if va in used_vas:
        return False
    used_vas.add(va)
    return True

def sort_entries_by_length_preserving_order(entries):
    return sorted(entries.items(), key=lambda x: -len(x[1].get('original', '')))

def process_entries(file_path, entries):
    pe = pefile.PE(file_path)
    with open(file_path, "rb") as f:
        data = f.read()

    sorted_entries = sort_entries_by_length_preserving_order(entries)
    results = []
    missing = []
    mismatches = []

    for key, entry in sorted_entries:
        original = entry.get("original")
        text = entry.get("text", original)
        expected_occ = entry.get("occurrences", [])

        offsets = find_exact_string(data, original)
        found_va = None
        for offset in offsets:
            va = get_va_from_offset(pe, offset)
            if is_va_unique(va):
                found_va = va
                break

        if not found_va:
            logging.warning(f"❌ '{original}' не найдена.")
            print(f"❌ '{original}' не найдена.")
            missing.append(original)
            continue

        le_bytes = va_to_le_bytes(found_va)
        if le_bytes is None:
            logging.warning(f"⚠️ Не удалось преобразовать VA для '{original}' в байты.")
            print(f"⚠️ Не удалось преобразовать VA для '{original}' в байты.")
            missing.append(original)
            continue

        occurrences = []
        start = 0
        while True:
            ref_offset = data.find(le_bytes, start)
            if ref_offset == -1:
                break
            ref_va = get_va_from_offset(pe, ref_offset)
            if ref_va:
                occurrences.append(ref_va)
            start = ref_offset + 1

        unique_sorted = sorted(set(occurrences))
        result_entry = {
            "string": original,
            "text": text,
            "va": found_va,
            "occurrences": unique_sorted
        }

        if expected_occ and len(expected_occ) != len(unique_sorted):
            logging.warning(f"⚠️ Несовпадение ссылок для '{original}': ожидалось {len(expected_occ)}, найдено {len(unique_sorted)}")
            print(f"⚠️ Несовпадение ссылок: '{original}' ожидалось {len(expected_occ)}, найдено {len(unique_sorted)}")
            mismatches.append(result_entry)
            if include_mismatches_in_main_output:
                results.append(result_entry)
        else:
            logging.info(f"✅ '{original}' найден по VA: {hex(found_va)}")
            print(f"✅ '{original}' найден по VA: {hex(found_va)}")
            logging.info(f"🔗 Occurrences: {[hex(o) for o in unique_sorted]}")
            print(f"🔗 Occurrences: {[hex(o) for o in unique_sorted]}")
            results.append(result_entry)

    return results, missing, mismatches

def export_results_to_json(results, output_path):
    export_data = {
        hex(item['va']): {
            "text": item['text'],
            "original": item['string'],
            "occurrences": [hex(o) for o in item['occurrences']]
        }
        for item in results
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=4, ensure_ascii=False)

    logging.info(f"📁 Экспорт завершён: {output_path}")
    print(f"\n📁 Экспорт завершён: {output_path}")

def export_missing_report(missing_list, report_path):
    with open(report_path, "w", encoding="utf-8") as f:
        for s in missing_list:
            f.write(s + "\n")
    logging.warning(f"📝 Отчёт о пропущенных строках сохранён: {report_path}")
    print(f"\n📝 Отчёт о пропущенных строках сохранён: {report_path}")

def export_mismatches_to_json(mismatches, output_path):
    export_data = {
        hex(item['va']): {
            "text": item['text'],
            "original": item['string'],
            "occurrences": [hex(o) for o in item['occurrences']]
        }
        for item in mismatches
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=4, ensure_ascii=False)

    logging.warning(f"📎 Несовпадающие строки сохранены в: {output_path}")
    print(f"\n📎 Несовпадающие строки сохранены в: {output_path}")

input_json = "Pointermap.json"
exe_path = "p3p_sln_DT_m.exe"
output_json = "newPointermap.json"

entries = load_original_entries(input_json)
results, missing, mismatches = process_entries(exe_path, entries)

export_results_to_json(results, output_json)
export_missing_report(missing, missing_log_path)

if not include_mismatches_in_main_output:
    export_mismatches_to_json(mismatches, mismatch_json_path)