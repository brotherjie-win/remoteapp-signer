import os
from typing import List, Optional


def list_folder_files(path: str, recursive: bool = True, included_ext: Optional[List[str]] = None,
                      excluded_ext: Optional[List[str]] = None) -> List[str]:
    """
    List all files in a folder (ignoring empty folders).
    :param path: file path (relative or absolute) of the folder you want to list its files.
    :param recursive: whether to list all files in subfolders recursively, True by default.
    :param included_ext: specific file extname you want to find on the folder, None by default.
    :param excluded_ext: specific file extname you don't want to exclude in the folder, None by default. Won't work when included_ext is set.
    :return: list of absolute paths of all files in the folder.
    """
    if included_ext is not None:
        for ext in included_ext:
            if not ext.startswith('.'):
                included_ext[included_ext.index(ext)] = '.' + ext
    elif excluded_ext is not None:
        for ext in excluded_ext:
            if not ext.startswith('.'):
                excluded_ext[excluded_ext.index(ext)] = '.' + ext
    file_list = []
    for entry in os.scandir(path):
        if entry.is_file():
            _, ext_name = os.path.splitext(entry.path)
            if included_ext is not None:
                if ext_name in included_ext:
                    file_list.append(entry.path)
            elif excluded_ext is not None:
                if ext_name not in excluded_ext:
                    file_list.append(entry.path)
            else:
                file_list.append(entry.path)
        elif entry.is_dir():
            if recursive:
                file_list.extend(list_folder_files(entry.path, recursive, included_ext, excluded_ext))
    return file_list


def calc_folder_files_num(path: str, recursive: bool = True, included_ext: Optional[List[str]] = None,
                          excluded_ext: Optional[List[str]] = None) -> int:
    """
    Calculate the number of files in a folder (ignoring empty folders).
    :param path: file path (relative or absolute) of the folder you want to list its files.
    :param recursive: whether to list all files in subfolders recursively, True by default.
    :param included_ext: specific file extname you want to find on the folder, None by default.
    :param excluded_ext: specific file extname you don't want to exclude in the folder, None by default. Won't work when included_ext is set.
    :return: number of files in the folder.
    """
    return len(list_folder_files(path, recursive, included_ext, excluded_ext))
