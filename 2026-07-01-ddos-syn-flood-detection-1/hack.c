/*
 * hack.c
 * SYN flood detection with handshake asymmetry on CICDDoS2019 Syn.csv
 * author @cocomelonc
 * This is defensive signal-processing code. It does not generate packets.
 */
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SAMPLES 500000
#define LINE_MAX_LEN 4096
#define EVENT_MERGE_GAP 60
#define EVENT_GRACE 3

typedef struct {
  int t;
  double flows;
  double fwd_pkts;
  double bwd_pkts;
  double syn_flags;
  double ack_flags;
  double oneway_flows;
  int label;

  double one_way_ratio;
  double fb_ratio;
  double volume_score_raw;
  double asym_score_raw;
  double volume_z;
  double asym_z;
  int volume_alert;
  int asym_alert;
} sample_t;

typedef struct {
  int tp;
  int fp;
  int fn;
  int events;
} metrics_t;

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
  double result = (n % 2 == 0) ? (tmp[n / 2 - 1] + tmp[n / 2]) / 2.0 : tmp[n / 2];
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
  return result < 1e-9 ? 1e-9 : result;
}

static char *trim(char *s) {
  while (isspace((unsigned char)*s)) {
    s++;
  }
  if (*s == 0) {
    return s;
  }
  char *end = s + strlen(s) - 1;
  while (end > s && isspace((unsigned char)*end)) {
    *end = 0;
    end--;
  }
  return s;
}

static int read_series(const char *path, sample_t *s) {
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
    exit(1);
  }

  char line[LINE_MAX_LEN];
  int n = 0;
  int line_no = 0;
  while (fgets(line, sizeof(line), f)) {
    line_no++;
    char *p = trim(line);
    if (*p == 0) {
      continue;
    }
    if (line_no == 1 && strstr(p, "flows") && strstr(p, "label")) {
      continue;
    }

    char *cols[8];
    for (int i = 0; i < 8; i++) {
      cols[i] = strtok(i == 0 ? p : NULL, ",");
      if (!cols[i]) {
        fprintf(stderr, "invalid CSV line %d\n", line_no);
        exit(1);
      }
    }
    if (n >= MAX_SAMPLES) {
      fprintf(stderr, "too many samples\n");
      exit(1);
    }

    s[n].t = atoi(trim(cols[0]));
    s[n].flows = atof(trim(cols[1]));
    s[n].fwd_pkts = atof(trim(cols[2]));
    s[n].bwd_pkts = atof(trim(cols[3]));
    s[n].syn_flags = atof(trim(cols[4]));
    s[n].ack_flags = atof(trim(cols[5]));
    s[n].oneway_flows = atof(trim(cols[6]));
    s[n].label = atoi(trim(cols[7])) != 0;
    n++;
  }

  fclose(f);
  return n;
}

static void compute_raw_features(sample_t *s, int n) {
  for (int i = 0; i < n; i++) {
    s[i].one_way_ratio = s[i].flows > 0.0 ? s[i].oneway_flows / s[i].flows : 0.0;
    s[i].fb_ratio = (s[i].fwd_pkts + 1.0) / (s[i].bwd_pkts + 1.0);

    /*
     * volume_score_raw is a basic flows/sec detector.
     *
     * asym_score_raw is a handshake-pressure proxy:
     * - more flows/sec increases pressure;
     * - high forward/backward packet ratio means weak response symmetry;
     * - one-way flows increase the score.
     */
    s[i].volume_score_raw = s[i].flows;
    s[i].asym_score_raw =
      s[i].flows *
      log1p(s[i].fb_ratio) *
      (1.0 + s[i].one_way_ratio);
  }
}

static int collect_benign(sample_t *s, int n, double *volume, double *asym) {
  int count = 0;
  for (int i = 0; i < n; i++) {
    if (s[i].label) {
      continue;
    }
    if (s[i].flows <= 0.0) {
      continue;
    }
    volume[count] = s[i].volume_score_raw;
    asym[count] = s[i].asym_score_raw;
    count++;
  }
  return count;
}

static metrics_t event_metrics(sample_t *s, int n, int use_asym) {
  metrics_t m = {0, 0, 0, 0};
  unsigned char *covered = (unsigned char *)calloc(n, sizeof(unsigned char));
  if (!covered) {
    perror("calloc");
    exit(1);
  }

  int i = 0;
  while (i < n) {
    if (!s[i].label) {
      i++;
      continue;
    }

    int start = i;
    int end = i;
    int last_attack = i;
    i++;

    while (i < n) {
      if (s[i].label) {
        last_attack = i;
        end = i;
        i++;
        continue;
      }
      if (i - last_attack <= EVENT_MERGE_GAP) {
        end = i;
        i++;
        continue;
      }
      break;
    }

    int grace_end = end + EVENT_GRACE;
    if (grace_end >= n) {
      grace_end = n - 1;
    }

    int detected = 0;
    for (int j = start; j <= grace_end; j++) {
      covered[j] = 1;
      int alert = use_asym ? s[j].asym_alert : s[j].volume_alert;
      if (alert) {
        detected = 1;
      }
    }

    m.events++;
    if (detected) {
      m.tp++;
    } else {
      m.fn++;
    }
  }

  for (i = 0; i < n; i++) {
    int alert = use_asym ? s[i].asym_alert : s[i].volume_alert;
    if (alert && !covered[i]) {
      m.fp++;
    }
  }

  free(covered);
  return m;
}

static void write_results(const char *path, sample_t *s, int n) {
  FILE *f = fopen(path, "w");
  if (!f) {
    fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
    exit(1);
  }

  fprintf(f, "t,flows,fwd_pkts,bwd_pkts,syn_flags,ack_flags,oneway_flows,label,one_way_ratio,fb_ratio,volume_raw,asym_raw,volume_z,asym_z,volume_alert,asym_alert\n");
  for (int i = 0; i < n; i++) {
    fprintf(f, "%d,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%d,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%d,%d\n",
      s[i].t,
      s[i].flows,
      s[i].fwd_pkts,
      s[i].bwd_pkts,
      s[i].syn_flags,
      s[i].ack_flags,
      s[i].oneway_flows,
      s[i].label,
      s[i].one_way_ratio,
      s[i].fb_ratio,
      s[i].volume_score_raw,
      s[i].asym_score_raw,
      s[i].volume_z,
      s[i].asym_z,
      s[i].volume_alert,
      s[i].asym_alert);
  }

  fclose(f);
}

int main(int argc, char **argv) {
  const char *input = "syn_handshake_timeseries.csv";
  const char *output = "syn_asym_results.csv";
  double volume_threshold = 8.0;
  double asym_threshold = 8.0;

  if (argc > 1) {
    input = argv[1];
  }
  if (argc > 2) {
    output = argv[2];
  }
  if (argc > 3) {
    volume_threshold = atof(argv[3]);
  }
  if (argc > 4) {
    asym_threshold = atof(argv[4]);
  }

  sample_t *samples = (sample_t *)calloc(MAX_SAMPLES, sizeof(sample_t));
  if (!samples) {
    perror("calloc");
    return 1;
  }

  int n = read_series(input, samples);
  if (n < 32) {
    fprintf(stderr, "need at least 32 samples\n");
    free(samples);
    return 1;
  }

  compute_raw_features(samples, n);

  double *benign_volume = (double *)malloc(sizeof(double) * n);
  double *benign_asym = (double *)malloc(sizeof(double) * n);
  if (!benign_volume || !benign_asym) {
    perror("malloc");
    free(samples);
    return 1;
  }

  int benign_n = collect_benign(samples, n, benign_volume, benign_asym);
  if (benign_n < 16) {
    fprintf(stderr, "not enough benign samples\n");
    free(benign_volume);
    free(benign_asym);
    free(samples);
    return 1;
  }

  double volume_med = median(benign_volume, benign_n);
  double volume_sigma = 1.4826 * mad(benign_volume, benign_n, volume_med);
  double asym_med = median(benign_asym, benign_n);
  double asym_sigma = 1.4826 * mad(benign_asym, benign_n, asym_med);

  for (int i = 0; i < n; i++) {
    samples[i].volume_z = (samples[i].volume_score_raw - volume_med) / volume_sigma;
    samples[i].asym_z = (samples[i].asym_score_raw - asym_med) / asym_sigma;
    samples[i].volume_alert = samples[i].volume_z > volume_threshold;
    samples[i].asym_alert = samples[i].asym_z > asym_threshold;
  }

  metrics_t volume_m = event_metrics(samples, n, 0);
  metrics_t asym_m = event_metrics(samples, n, 1);

  printf("input: %s\n", input);
  printf("samples: %d\n", n);
  printf("benign samples for baseline: %d\n", benign_n);
  printf("volume median: %.8f robust sigma: %.8f threshold z: %.2f\n",
    volume_med, volume_sigma, volume_threshold);
  printf("asym median: %.8f robust sigma: %.8f threshold z: %.2f\n\n",
    asym_med, asym_sigma, asym_threshold);

  printf("event-level volume detector:             TP=%d FP=%d FN=%d events=%d\n",
    volume_m.tp, volume_m.fp, volume_m.fn, volume_m.events);
  printf("event-level handshake asymmetry detector: TP=%d FP=%d FN=%d events=%d\n",
    asym_m.tp, asym_m.fp, asym_m.fn, asym_m.events);

  write_results(output, samples, n);
  printf("\nwrote %s\n", output);

  free(benign_volume);
  free(benign_asym);
  free(samples);
  return 0;
}
