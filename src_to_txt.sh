#!/bin/bash

# srcディレクトリ以下のすべての.rsファイルを1つのtxtファイルに出力するスクリプト

OUTPUT_FILE="src_files_combined.txt"

# 出力ファイルが存在する場合は削除
if [ -f "$OUTPUT_FILE" ]; then
    rm "$OUTPUT_FILE"
fi

echo "=== srcディレクトリ以下の.rsファイルを結合中 ===" > "$OUTPUT_FILE"
echo "生成日時: $(date)" >> "$OUTPUT_FILE"
echo "===============================================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# srcディレクトリ内の.rsファイルを検索して結合
find src -name "*.rs" -type f | sort | while read -r file; do
    echo "=== ファイル: $file ===" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    cat "$file" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "===============================================" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
done

echo "完了！すべての.rsファイルが $OUTPUT_FILE に結合されました。"
echo "ファイル数: $(find src -name "*.rs" -type f | wc -l)"
echo "出力ファイルサイズ: $(du -h "$OUTPUT_FILE" | cut -f1)" 