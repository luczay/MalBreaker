import pefile


class PEFile:
    def __init__(self, target_path: str):
        self.pe = pefile.PE(target_path)

    def get_pe_version_info(self) -> list:
        file_info = []
        
        if hasattr(self.pe, 'FileInfo'):
            for file_info in self.pe.FileInfo:
                if file_info.Key == b'StringFileInfo':
                    for string_table in file_info.StringTable:
                        for entry_key, entry_value in string_table.entries.items():
                            file_info.append({"name": entry_key.decode('utf-8'), "detail": entry_value.decode('utf-8')})

        return file_info
    

    def extract_details(self):
        imports = self._get_imports()
        exports = self._get_exports()
        resources = self._get_resources()
        tls_callback = self._find_tls_callback()
        signature = self._find_signature()

        return {"imports": imports, "exports": exports, "resources": resources, "tls_callback": tls_callback, "signature": signature}
    

    def close(self):
        self.pe.close()
    

    def _get_imports(self):
        imports = []

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            import_entry = entry.dll.decode()
            entry_imports = []

            for imp in entry.imports:
                entry_imports.append(f"{imp.name.decode() if imp.name else 'Ordinal'}")

            imports.append({"import_entry": import_entry, "entry_imports": entry_imports})

        return imports
        
    
    def _get_exports(self):
        exports = []

        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append(exp.name.decode() if exp.name else "Unnamed Export")

        return exports
    

    def _get_resources(self):
        resources = []

        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                resources.append(f"Resource Type: {resource.struct.Id}")

        return resources
    

    def _find_tls_callback(self):
        tls_callback = ""

        if hasattr(self.pe, 'DIRECTORY_ENTRY_TLS') and self.pe.DIRECTORY_ENTRY_TLS:
            tls_callback = f"TLS Callback at: {hex(self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)}"
        else:
            tls_callback = "No TLS Callback"

        return tls_callback
    
    def _find_signature(self):
        signature = ""

        if hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
            signature = "Target has a digital signature"
        else:
            signature = "No digital signature found"

        return signature