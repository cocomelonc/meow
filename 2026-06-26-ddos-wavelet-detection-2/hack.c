/*
 * hack.c
 * Daubechies D4 wavelet detector for DDoS-like traffic anomalies
 * analyzes a time series extracted from traffic data
 * author @cocomelonc
 */
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SAMPLES 200000
#define LINE_MAX_LEN 4096
#define AVG_WINDOW 16
#define BASELINE_LIMIT 256
#define EVENT_GRACE 3

typedef struct {
  int t;
  double value;
  int label;
  double rolling_avg;
  double db4_detail;
  double db4_score;
  int avg_alert;
  int db4_alert;
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

static int read_series(const char *path, sample_t *samples) {
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

    if (line_no == 1 && strstr(p, "t") && strstr(p, "value")) {
      continue;
    }

    char *t_s = strtok(p, ",");
    char *value_s = strtok(NULL, ",");
    char *label_s = strtok(NULL, ",");

    if (!t_s || !value_s || !label_s) {
      fprintf(stderr, "invalid CSV line %d\n", line_no);
      exit(1);
    }

    if (n >= MAX_SAMPLES) {
      fprintf(stderr, "too many samples, max=%d\n", MAX_SAMPLES);
      exit(1);
    }

    samples[n].t = atoi(trim(t_s));
    samples[n].value = atof(trim(value_s));
    samples[n].label = atoi(trim(label_s)) != 0;
    samples[n].rolling_avg = 0.0;
    samples[n].db4_detail = 0.0;
    samples[n].db4_score = 0.0;
    samples[n].avg_alert = 0;
    samples[n].db4_alert = 0;
    n++;
  }

  fclose(f);
  return n;
}

static void compute_rolling_avg(sample_t *s, int n) {
  for (int i = 0; i < n; i++) {
    int start = i - AVG_WINDOW + 1;
    if (start < 0) {
      start = 0;
    }

    double sum = 0.0;
    int count = 0;
    for (int j = start; j <= i; j++) {
      sum += s[j].value;
      count++;
    }
    s[i].rolling_avg = sum / (double)count;
  }
}

static void compute_db4_detail(sample_t *s, int n) {
  const double sqrt3 = 1.7320508075688772935;
  const double denom = 4.0 * 1.4142135623730950488;

  const double h0 = (1.0 + sqrt3) / denom;
  const double h1 = (3.0 + sqrt3) / denom;
  const double h2 = (3.0 - sqrt3) / denom;
  const double h3 = (1.0 - sqrt3) / denom;

  /*
   * High-pass decomposition filter for Daubechies D4.
   * This is the quadrature mirror filter:
   * g[k] = (-1)^k h[3-k]
   */
  const double g0 = h3;
  const double g1 = -h2;
  const double g2 = h1;
  const double g3 = -h0;

  for (int i = 3; i < n; i++) {
    s[i].db4_detail =
      g0 * s[i - 3].value +
      g1 * s[i - 2].value +
      g2 * s[i - 1].value +
      g3 * s[i].value;
    s[i].db4_detail = fabs(s[i].db4_detail);
  }
}

static int collect_baseline_details(sample_t *s, int n, double *out) {
  int count = 0;
  for (int i = 3; i < n && count < BASELINE_LIMIT; i++) {
    if (s[i].label) {
      break;
    }
    out[count++] = s[i].db4_detail;
  }
  return count;
}

static metrics_t event_metrics(sample_t *s, int n, int use_db4) {
  metrics_t m = {0, 0, 0, 0};

  int covered[MAX_SAMPLES];
  memset(covered, 0, sizeof(covered));

  int i = 0;
  while (i < n) {
    if (!s[i].label) {
      i++;
      continue;
    }

    int start = i;
    while (i < n && s[i].label) {
      i++;
    }
    int end = i - 1;
    int grace_end = end + EVENT_GRACE;
    if (grace_end >= n) {
      grace_end = n - 1;
    }

    int detected = 0;
    for (int j = start; j <= grace_end; j++) {
      covered[j] = 1;
      int alert = use_db4 ? s[j].db4_alert : s[j].avg_alert;
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
    int alert = use_db4 ? s[i].db4_alert : s[i].avg_alert;
    if (alert && !covered[i]) {
      m.fp++;
    }
  }

  return m;
}

static void write_results(const char *path, sample_t *s, int n) {
  FILE *f = fopen(path, "w");
  if (!f) {
    fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
    exit(1);
  }

  fprintf(f, "t,value,label,rolling_avg,db4_detail,db4_score,avg_alert,db4_alert\n");
  for (int i = 0; i < n; i++) {
    fprintf(f, "%d,%.8f,%d,%.8f,%.8f,%.8f,%d,%d\n",
      s[i].t,
      s[i].value,
      s[i].label,
      s[i].rolling_avg,
      s[i].db4_detail,
      s[i].db4_score,
      s[i].avg_alert,
      s[i].db4_alert);
  }

  fclose(f);
}

int main(int argc, char **argv) {
  const char *input = "fixture_cic_timeseries.csv";
  const char *output = "db4_results.csv";
  double avg_threshold = 600.0;
  double db4_threshold = 8.0;

  if (argc > 1) {
    input = argv[1];
  }
  if (argc > 2) {
    output = argv[2];
  }
  if (argc > 3) {
    avg_threshold = atof(argv[3]);
  }
  if (argc > 4) {
    db4_threshold = atof(argv[4]);
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

  compute_rolling_avg(samples, n);
  compute_db4_detail(samples, n);

  double baseline[BASELINE_LIMIT];
  int baseline_n = collect_baseline_details(samples, n, baseline);
  if (baseline_n < 16) {
    fprintf(stderr, "not enough benign baseline samples before the first attack\n");
    free(samples);
    return 1;
  }

  double med = median(baseline, baseline_n);
  double sigma = 1.4826 * mad(baseline, baseline_n, med);

  for (int i = 0; i < n; i++) {
    samples[i].db4_score = (samples[i].db4_detail - med) / sigma;
    samples[i].avg_alert = samples[i].rolling_avg > avg_threshold;
    samples[i].db4_alert = samples[i].db4_score > db4_threshold;
  }

  metrics_t avg_m = event_metrics(samples, n, 0);
  metrics_t db4_m = event_metrics(samples, n, 1);

  printf("input: %s\n", input);
  printf("samples: %d\n", n);
  printf("baseline samples: %d\n", baseline_n);
  printf("db4 detail median: %.8f\n", med);
  printf("db4 detail robust sigma: %.8f\n", sigma);
  printf("rolling average threshold: %.2f\n", avg_threshold);
  printf("db4 z-score threshold: %.2f\n\n", db4_threshold);

  printf("event-level rolling average: TP=%d FP=%d FN=%d events=%d\n",
    avg_m.tp, avg_m.fp, avg_m.fn, avg_m.events);
  printf("event-level Daubechies D4:  TP=%d FP=%d FN=%d events=%d\n",
    db4_m.tp, db4_m.fp, db4_m.fn, db4_m.events);

  write_results(output, samples, n);
  printf("\nwrote %s\n", output);

  free(samples);
  return 0;
}
