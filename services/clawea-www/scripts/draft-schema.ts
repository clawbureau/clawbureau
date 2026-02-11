import { z } from "zod";

export const DraftFaqSchema = z.object({
  q: z.string().min(8).max(140),
  a: z.string().min(30).max(600),
});

export const DraftStepSchema = z.object({
  name: z.string().min(3).max(80),
  text: z.string().min(20).max(300),
});

export const DraftSectionSchema = z.object({
  heading: z.string().min(5).max(90),
  paragraphs: z.array(z.string().min(40).max(500)).min(1).max(4),
  bullets: z.array(z.string().min(10).max(200)).max(8).optional(),
  /**
   * Optional "so what" sentence: risk reduction, audit impact, cost control, speed, or compliance.
   * Include when it materially helps the reader make a decision.
   */
  impact: z.string().min(30).max(240).optional(),
});

export const DraftCitationSchema = z.object({
  title: z.string().min(2).max(120),
  url: z.string().url(),
});

export const DraftTemplatesSchema = z.object({
  openclawConfigJson5: z.string().min(20).max(4000).optional(),
  envVars: z.array(z.string().min(3).max(120)).max(20).optional(),
  wpcExampleJson: z.string().min(20).max(4000).optional(),
  deployCurl: z.string().min(10).max(1500).optional(),
});

export const ArticleDraftSchema = z.object({
  metaDescription: z.string().min(80).max(220),
  directAnswer: z.string().min(60).max(450),
  intro: z.string().min(80).max(650),
  howToTitle: z.string().min(10).max(90),
  howToSteps: z.array(DraftStepSchema).min(3).max(7),
  sections: z.array(DraftSectionSchema).min(3).max(8),
  faqs: z.array(DraftFaqSchema).min(3).max(6),
  citations: z.array(DraftCitationSchema).min(2).max(8),
  caveats: z.array(z.string().min(10).max(200)).max(6).optional(),
  templates: DraftTemplatesSchema.optional(),
});

export type ArticleDraft = z.infer<typeof ArticleDraftSchema>;
