import DomainPageModel from "../models/DomainPage.js";
import nodemailer from "nodemailer";

// Create a new DomainPage
export const createDomainPage = async (req, res) => {
   try {
      const { domainName } = req.body;

      // Check if the domainName already exists
      const existingDomainPage = await DomainPageModel.findOne({ domainName });

      if (existingDomainPage) {
         // If it exists, increment the count and update the document
         existingDomainPage.count += 1;
         await existingDomainPage.save();

         //Mail
         if(existingDomainPage.count > 5 ){
            console.log("Sending Alert Mail")
            const transporter = nodemailer.createTransport({
               service:"Gmail",
               auth: {
                  user: process.env.GMAIL_USER,
                  pass: process.env.GMAIL_PASS,
               },
            });
               
            const options = {
               from: process.env.GMAIL_USER,
               to: process.env.ALERT_RECIPIENTS,
               subject: "Reporting Malicious Networks✔", // Subject line
               text: `Urgently request your expertise as a cybercrime specialist to review the website ${domainName}. Numerous user reports have raised concerns about its potential involvement in phishing or malicious activities. Your assessment is crucial in determining the legitimacy and threat level of this website, ensuring the safety of online users..`, // plain text body
            };
               
            transporter.sendMail(options,function(err,info){
               if(err){
                  console.log(err);
                  return;
               }
               console.log("SENT : " + info.response);
            })
   
         }
         return res.status(200).json(existingDomainPage);
      } else {
         // If it doesn't exist, create a new document
         const newDomainPage = new DomainPageModel({ domainName });
         await newDomainPage.save();
         return res.status(201).json(newDomainPage);
      }
   } catch (error) {
      return res.status(500).json({ message: "Internal Server Error" });
   }
};

// Get all DomainPages
export const getAllDomainPages = async (req, res) => {
   try {
      const domainPages = await DomainPageModel.find();
      return res.status(200).json(domainPages);
   } catch (error) {
      return res.status(500).json({ message: "Internal Server Error" });
   }
};

// Get a DomainPage by ID
export const getDomainPageById = async (req, res) => {
   try {
      const { id } = req.params;
      const domainPage = await DomainPageModel.findById(id);

      if (!domainPage) {
         return res.status(404).json({ message: "DomainPage not found" });
      }

      return res.status(200).json(domainPage);
   } catch (error) {
      return res.status(500).json({ message: "Internal Server Error" });
   }
};

// Update a DomainPage by ID
export const updateDomainPage = async (req, res) => {
   try {
      const { id } = req.params;
      const { domainName, count } = req.body;
      const updatedDomainPage = await DomainPageModel.findByIdAndUpdate(
         id,
         { domainName, count },
         { new: true }
      );

      if (!updatedDomainPage) {
         return res.status(404).json({ message: "DomainPage not found" });
      }

      return res.status(200).json(updatedDomainPage);
   } catch (error) {
      return res.status(500).json({ message: "Internal Server Error" });
   }
};

// Delete a DomainPage by ID
export const deleteDomainPage = async (req, res) => {
   try {
      const { id } = req.params;
      const deletedDomainPage = await DomainPageModel.findByIdAndRemove(id);

      if (!deletedDomainPage) {
         return res.status(404).json({ message: "DomainPage not found" });
      }

      return res.status(200).json({ message: "DomainPage deleted successfully" });
   } catch (error) {
      return res.status(500).json({ message: "Internal Server Error" });
   }
};
