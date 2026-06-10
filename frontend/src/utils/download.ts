export const triggerDownload = async (filename: string, contentOrBlob: string | Blob, isPcap: boolean = false) => {
  // @ts-ignore
  if (window.pywebview && window.pywebview.api) {
    if (isPcap) {
      // @ts-ignore
      await window.pywebview.api.save_pcap(filename);
      return;
    }

    let blob = contentOrBlob;
    if (typeof contentOrBlob === 'string') {
      blob = new Blob([contentOrBlob], { type: 'text/plain' });
    }
    const reader = new FileReader();
    reader.readAsDataURL(blob as Blob);
    reader.onloadend = async () => {
      const result = reader.result as string;
      const base64data = result.substring(result.indexOf(',') + 1);
      // @ts-ignore
      await window.pywebview.api.save_base64(filename, base64data);
    };
  } else {
    // Fallback for regular web browser
    const a = document.createElement('a');
    let blob = contentOrBlob;
    if (typeof contentOrBlob === 'string') {
      blob = new Blob([contentOrBlob], { type: 'text/plain' });
    } else if (isPcap) {
      // For pcap fallback, we assume contentOrBlob is the blob
      blob = contentOrBlob;
    }
    a.href = URL.createObjectURL(blob as Blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }
};
