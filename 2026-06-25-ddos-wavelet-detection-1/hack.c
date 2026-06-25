/*
 * hack.c
 * simple Haar wavelet PoC for detecting short traffic anomalies
 * author @cocomelonc
 *
 * This program does not generate packets and does not attack anything.
 * It simulates packet-rate samples and compares a rolling-average detector
 * with a first-level Haar wavelet detector.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 256
#define AVG_WINDOW 16
#define BASELINE_N 100

typedef struct {
  int t;
  double traffic;
  double rolling_avg;
  double haar_detail;
  double wavelet_score;
  int avg_alert;
  int wavelet_alert;
  int is_attack;
} sample_t;

static int cmp_double(const void *a, const void *b) {
  double x = *(const double *)a;
  double y = *(const double *)b;
  return (x > y) - (x < y);
}

static double median(double *v, int n) {
  double *tmp = (double *)malloc(sizeof(double) * n);
  if (!tmp) {
    perror("malloc");
    exit(1);
  }

  memcpy(tmp, v, sizeof(double) * n);
  qsort(tmp, n, sizeof(double), cmp_double);

  double result;
  if (n % 2 == 0) {
    result = (tmp[n / 2 - 1] + tmp[n / 2]) / 2.0;
  } else {
    result = tmp[n / 2];
  }

  free(tmp);
  return result;
}

static double mad(double *v, int n, double med) {
  double *dev = (double *)malloc(sizeof(double) * n);
  if (!dev) {
    perror("malloc");
    exit(1);
  }

  for (int i = 0; i < n; i++) {
    dev[i] = fabs(v[i] - med);
  }

  double result = median(dev, n);
  free(dev);

  if (result < 1e-9) {
    return 1e-9;
  }
  return result;
}

static int is_attack_time(int t) {
  return (t >= 120 && t <= 122) || (t >= 180 && t <= 182);
}

static int in_event_window(int t, int start, int end) {
  return t >= start && t <= end + 1;
}

static double synthetic_traffic(int t) {
  /*
   * Normal traffic is around 10k packets/sec with slow periodic variation.
   * Attack traffic is a short pulse. Its duration is intentionally short:
   * a rolling average over 16 samples should not cross the threshold.
   */
  double baseline = 10.0 + 1.5 * sin((2.0 * M_PI * t) / 64.0);
  double tiny_noise = (double)((t * 37) % 11) / 20.0;

  if (t >= 120 && t <= 122) {
    return 80.0 + tiny_noise;
  }
  if (t >= 180 && t <= 182) {
    return 70.0 + tiny_noise;
  }
  return baseline + tiny_noise;
}

int main(void) {
  sample_t s[N];
  double baseline_details[BASELINE_N - 1];

  for (int i = 0; i < N; i++) {
    s[i].t = i;
    s[i].traffic = synthetic_traffic(i);
    s[i].is_attack = is_attack_time(i);

    int start = i - AVG_WINDOW + 1;
    if (start < 0) {
      start = 0;
    }

    double sum = 0.0;
    int count = 0;
    for (int j = start; j <= i; j++) {
      sum += s[j].traffic;
      count++;
    }

    s[i].rolling_avg = sum / (double)count;
    s[i].haar_detail = 0.0;
    if (i > 0) {
      s[i].haar_detail = fabs(s[i].traffic - s[i - 1].traffic) / sqrt(2.0);
    }
  }

  for (int i = 1; i < BASELINE_N; i++) {
    baseline_details[i - 1] = s[i].haar_detail;
  }

  double med = median(baseline_details, BASELINE_N - 1);
  double sigma = 1.4826 * mad(baseline_details, BASELINE_N - 1, med);

  const double avg_threshold = 30.0;
  const double wavelet_threshold = 8.0;

  for (int i = 0; i < N; i++) {
    s[i].wavelet_score = (s[i].haar_detail - med) / sigma;
    s[i].avg_alert = s[i].rolling_avg > avg_threshold;
    s[i].wavelet_alert = s[i].wavelet_score > wavelet_threshold;
  }

  int event_start[] = {120, 180};
  int event_end[] = {122, 182};
  int event_count = 2;

  int avg_event_tp = 0;
  int wav_event_tp = 0;

  for (int e = 0; e < event_count; e++) {
    int avg_seen = 0;
    int wav_seen = 0;
    for (int i = 0; i < N; i++) {
      if (!in_event_window(i, event_start[e], event_end[e])) {
        continue;
      }
      if (s[i].avg_alert) {
        avg_seen = 1;
      }
      if (s[i].wavelet_alert) {
        wav_seen = 1;
      }
    }
    avg_event_tp += avg_seen;
    wav_event_tp += wav_seen;
  }

  int avg_event_fp = 0;
  int wav_event_fp = 0;
  for (int i = 0; i < N; i++) {
    int inside_any_event = 0;
    for (int e = 0; e < event_count; e++) {
      if (in_event_window(i, event_start[e], event_end[e])) {
        inside_any_event = 1;
      }
    }
    if (!inside_any_event && s[i].avg_alert) {
      avg_event_fp++;
    }
    if (!inside_any_event && s[i].wavelet_alert) {
      wav_event_fp++;
    }
  }

  int avg_event_fn = event_count - avg_event_tp;
  int wav_event_fn = event_count - wav_event_tp;

  FILE *f = fopen("wavelet_ddos.csv", "w");
  if (!f) {
    perror("fopen");
    return 1;
  }

  fprintf(f, "t,traffic,rolling_avg,haar_detail,wavelet_score,avg_alert,wavelet_alert,is_attack\n");
  for (int i = 0; i < N; i++) {
    fprintf(f, "%d,%.6f,%.6f,%.6f,%.6f,%d,%d,%d\n",
      s[i].t,
      s[i].traffic,
      s[i].rolling_avg,
      s[i].haar_detail,
      s[i].wavelet_score,
      s[i].avg_alert,
      s[i].wavelet_alert,
      s[i].is_attack);
  }
  fclose(f);

  printf("baseline Haar detail median: %.6f\n", med);
  printf("baseline Haar detail robust sigma: %.6f\n", sigma);
  printf("rolling average threshold: %.2f\n", avg_threshold);
  printf("wavelet z-score threshold: %.2f\n\n", wavelet_threshold);

  printf("event-level rolling average detector: TP=%d FP=%d FN=%d\n",
    avg_event_tp, avg_event_fp, avg_event_fn);
  printf("event-level Haar wavelet detector:    TP=%d FP=%d FN=%d\n",
    wav_event_tp, wav_event_fp, wav_event_fn);
  printf("\nwrote wavelet_ddos.csv\n");

  return 0;
}
