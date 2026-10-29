const MAX_FILE_SIZE = 19 * 1024 * 1024;

export function validateProjectFile(file) {
  if (!file) return "";
  if (file.size === 0) {
    return "The file is empty. Please upload a file containing data.";
  }
  if (!file.name.toLowerCase().endsWith(".zip")) {
    return "Choose a ZIP archive containing your Python or FastAPI project.";
  }
  if (file.size > MAX_FILE_SIZE) {
    return "The file exceeds the 19 MiB limit. Please upload a smaller file.";
  }
  return "";
}
