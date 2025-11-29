import os
from crowdin_api import CrowdinClient
from dotenv import load_dotenv

# --- 配置  ---
load_dotenv()
PROJECT_ID = os.getenv("PROJECT_ID")
# 注意：在实际使用中，请确保使用 os.getenv() 来加载敏感信息
PERSONAL_TOKEN = os.getenv("PERSONAL_TOKEN")
LOCAL_SOURCE_ROOT = "docs"
TARGET_LANGUAGES = ["zh"]
IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp')

# --- Crowdin API 客户端初始化 (保持不变) ---
class CustomClient(CrowdinClient):
    """自定义客户端以处理凭证"""
    def __init__(self, token, project_id, organization=None):
        super().__init__(token=token, organization=organization)
        self.project_id = project_id

client = CustomClient(
    token=PERSONAL_TOKEN,
    project_id=PROJECT_ID,
)

# --- 核心逻辑函数 (保持不变) ---
# upload_translation 和 check_translation_status 保持不变
# ... [此处省略 upload_translation 和 check_translation_status 函数] ...

def get_crowdin_file_id(crowdin_path):
    """
    通过 Crowdin 路径查找对应的文件 ID。
    
    :param crowdin_path: 文件在 Crowdin 中的路径 (例如: /docs/intro.png)
    :return: 文件 ID 或 None
    """
    try:
        # 查找项目中的所有文件
        response = client.source_files.list_files(
            projectId=PROJECT_ID,
            limit=500  # 根据项目文件数调整
        )
        
        for item in response['data']:
            file_data = item['data']
            # Crowdin API 返回的路径是 path + name 的组合，但这里只取 path
            full_crowdin_path = file_data.get('path', '') + file_data.get('name', '')
            
            # 去掉可能的 /main/ 前缀
            if full_crowdin_path.startswith('/main'):
                full_crowdin_path = full_crowdin_path.split('/main', 1)[1]
            
            # 确保 full_crowdin_path 匹配 crowdin_path (例如: /docs/intro.png)
            if full_crowdin_path.endswith(crowdin_path):
                # print(f"  -> 找到 Crowdin 文件: ID {file_data['id']}")
                return file_data['id']
                
    except Exception as e:
        print(f"❌ 查找 Crowdin 文件时出错: {e}")
        return None


def get_untranslated_files_info():
    """
    获取 Crowdin 项目中所有翻译进度不满 100% 的文件信息。
    
    :return: 一个字典，键是 (file_id, language_code)，值是当前翻译进度 (int)。
    """
    untranslated_files_info = {}
    print("--- 1. 获取项目所有文件及翻译进度 ---")
    
    try:
        # 获取项目的整体进度，它包含了所有文件的进度信息
        response = client.translation_status.get_project_progress(
            projectId=PROJECT_ID,
            # optional: is_translated_only=False (默认为 False，获取所有文件)
        )
        
        for lang_data in response['data']:
            language_id = lang_data['data']['languageId']
            
            if language_id in TARGET_LANGUAGES:
                print(f"  检查语言: {language_id}")
                
                # 遍历文件进度信息
                for file_progress in lang_data['data'].get('files', []):
                    file_id = file_progress['id']
                    progress = file_progress['translationProgress']
                    file_name = file_progress.get('name', f"File ID: {file_id}")
                    
                    # 筛选出未完成翻译的文件 (进度 < 100%)
                    if progress < 100:
                        # 存储 (file_id, language_code) -> progress
                        untranslated_files_info[(file_id, language_id)] = progress
                        print(f"    - [未完成] 文件: {file_name} ({file_id}), 进度: {progress}%")

    except Exception as e:
        print(f"❌ 获取项目进度时出错: {e}")
    
    print(f"\n✅ 进度获取完成。共找到 {len(untranslated_files_info)} 个待处理的文件/语言组合。")
    return untranslated_files_info

def main():
    if not os.path.isdir(LOCAL_SOURCE_ROOT):
        print(f"错误: 找不到本地源目录 '{LOCAL_SOURCE_ROOT}'。请检查路径。")
        return

    # 1. 获取所有未翻译完成的文件信息
    untranslated_files = get_untranslated_files_info()
    
    if not untranslated_files:
        print("所有目标语言的文件都已翻译完成或未找到未完成文件，程序结束。")
        return

    # 2. 获取 Crowdin 中所有文件的元数据（我们需要文件名和路径来判断是否是图片）
    print("\n--- 2. 获取 Crowdin 文件元数据以匹配本地路径 ---")
    crowdin_file_map = {} # {file_id: '/docs/path/to/file.png'}
    try:
        response = client.source_files.list_files(projectId=PROJECT_ID, limit=5000)
        for item in response['data']:
            file_data = item['data']
            file_id = file_data['id']
            full_path = file_data.get('path', '') + file_data.get('name', '')
            
            # 去掉可能的 /main/ 前缀
            if full_path.startswith('/main'):
                full_path = full_path.split('/main', 1)[1]
                
            crowdin_file_map[file_id] = full_path
    except Exception as e:
        print(f"❌ 获取 Crowdin 文件列表失败: {e}")
        return

    print("✅ Crowdin 文件元数据获取完成。")
    
    # 3. 遍历未翻译完成的文件，筛选图片并处理
    print("\n--- 3. 筛选并处理未翻译的图片文件 ---")
    
    for (file_id, lang_code), progress in untranslated_files.items():
        crowdin_full_path = crowdin_file_map.get(file_id)
        
        if not crowdin_full_path:
            # 文件可能已被删除或API数据不完整，跳过
            continue
        
        # 判断是否是图片文件
        if crowdin_full_path.lower().endswith(IMAGE_EXTENSIONS):
            # 确定本地文件路径：将 Crowdin 路径 (/docs/...) 转换为本地路径 (docs/...)
            # 注意：移除开头的斜杠
            local_file_path = crowdin_full_path.lstrip('/')
            
            if os.path.exists(local_file_path):
                print(f"\n处理图片文件: {crowdin_full_path} -> 进度 {progress}% for {lang_code}")
                
                # 执行上传操作 (将源文件作为翻译结果)
                upload_translation(file_id, local_file_path, lang_code)
                
            else:
                print(f"  ⚠️ 警告: 本地文件未找到，跳过: {local_file_path}")
        # else:
            # 如果不是图片文件，则跳过 (这些是 Markdown 文档等需要人工翻译的文件)
            
    print("\n--- 任务完成 ---")


if __name__ == "__main__":
    
    # 由于您的 token 是硬编码的，这里需要重新定义函数以供执行
    def upload_translation(file_id, local_file_path, language_code):
        print(f"  -> [Mock] 上传 {os.path.basename(local_file_path)} 到 {language_code}...")
        # 实际代码
        try:
            storage_response = client.storages.add_storage(file=local_file_path)
            storage_id = storage_response['data']['id']
            client.translations.upload_translation(
                projectId=PROJECT_ID,
                languageId=language_code,
                storageId=storage_id,
                fileId=file_id,
                importDuplicates=True 
            )
            print(f"  ✅ 成功为 {language_code} 上传翻译。")
        except Exception as e:
            print(f"  ❌ 为 {language_code} 上传翻译失败: {e}")

    main()