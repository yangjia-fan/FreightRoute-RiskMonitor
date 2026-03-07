## Freight Route Risk Monitor

*Note: Refer to **Setup.md** for instructions on loading the app on your local computer

A modular tool for monitoring maritime security incidents using UKTMO.org and estimating route-specific geopolitical risk exposure for shipping lanes imported from company ops. Further development could be to link the tool to more robust marinetraffic sources like Kpler.

The goal of this project is to prototype how real-time security intelligence could be integrated into freight trading or logistics decision workflows. Using publicly available UKMTO incident reports, the system maps incidents geographically and computes a risk index for selected routes based on severity, recency, and proximity.

This is not meant to be a full intelligence platform, but rather a proof-of-concept showing how geopolitical risk signals can be quantified and visualized alongside shipping routes, which could be later used as a multiplier in a downstream valuation of the underlying cargo transiting via the route


### Pipeline:

1. Pulls maritime incident reports from the UKMTO API
2. Scores incident severity using a deterministic keyword-based NLP lexicon
3. Classifies events (e.g. kinetic attack, suspicious activity, EW interference)
4. Calculates route-dependent exposure by measuring distance from incidents to a selected shipping lane
5. Computes a bounded Risk Index (0–100) using severity, recency decay, and proximity weighting
6. Displays incidents and risk metrics on an interactive map interface

Because proximity is calculated relative to a selected route, the same incidents can produce different risk levels for different freight lanes.



### **RISK INDEX Details**

The system aggregates incidents using a simple weighted model.

	RawRisk = Σ (severity × recency × proximity)


#### **SEVERITY**

The severity score is derived from the incident description using a deterministic keyword and context scoring rule. Terms associated with weapons, attacks, damage, or casualties increase the score, while language indicating uncertainty or lack of harm (e.g., “no injuries”, “suspected”, “attempted”) reduces it.

	Interpretation of the scale:
	- Suspicious activity or approach → low severity
	- Boarding attempts or hostile interaction → moderate severity
	- Confirmed attacks involving weapons, explosions, or casualties → high severity

The score is capped at 20 to prevent a single incident from dominating the overall risk calculation.


#### **RECENCY**

Recent incidents carry greater weight using exponential decay:

	recency = 0.5^(age_days / half_life_days)

The half-life parameter determines how quickly incidents lose influence.


#### **PROXIMITY**

Events closer to the route are more relevant:

	proximity = exp(−distance_to_lane_km / radius_km)


#### **Risk Index**

The aggregated score is mapped into a bounded scale:

	RiskIndex = 100 × (1 − exp(−RawRisk / 15))

This prevents the metric from exploding during clusters of incidents while still reflecting rising risk.



**EXAMPLE ROUTES**

The prototype includes example shipping lanes such as:

	- Kuwait → Qatar
	- Kuwait → Dubai
	- Qatar → Arabian Sea

Risk is recomputed instantly when switching routes.



### **POSSIBLE EXTENSIONS**

This prototype intentionally keeps the model simple. Natural next steps could include:

- integrating AIS vessel traffic
- estimating vessel exposure to risk corridors
- linking freight rates to security conditions
- incorporating geopolitical event feeds
- building alerting for sudden risk spikes


### **MOTIVATION**

Freight trading and maritime logistics operate in environments where geopolitical developments can quickly alter risk conditions for shipping lanes. Yet these signals are often qualitative or fragmented across different sources.

This project explores a simple framework for transforming incident reports into a quantitative risk signal that can be tied to specific routes and updated in real time.
