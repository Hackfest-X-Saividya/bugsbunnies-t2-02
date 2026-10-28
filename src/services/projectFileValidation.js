const MAX_FILE_SIZE = 50 * 1024 * 1024;

export function validateProjectFile(file) {
  if (!file) return "";
  if (file.size === 0) {
    return "The file is empty. Please upload a file containing data.";
  }
  if (!file.name.toLowerCase().endsWith(".zip")) {
    return "Choose a ZIP archive containing your Python or FastAPI project.";
  }
  if (file.size > MAX_FILE_SIZE) {
    return "This file exceeds the 50 MB limit. Choose a smaller ZIP archive.";
  }
  return "";
}
